#[allow(unused_imports)]
use log::*;
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Display, Write},
    path::{Path, PathBuf},
    str,
};

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine,
};
use chrono::{DateTime, Local, TimeZone};
use git2::{cert::Cert, CertificateCheckStatus, Oid};
use hmac::Mac;
use sha2::{Digest, Sha256};

use crate::{
    crypto::{Crypto, FindSigningFingerprintStrategy, PassphraseProvider, VerificationError},
    error::{Error, Result},
    pass::{to_result, PasswordEntry, PasswordStore, RepositoryStatus},
    signature::SignatureStatus,
};

const HASH_HOSTNAME_PREFIX: &str = "|1|";

fn git_branch_name(repo: &git2::Repository) -> Result<String> {
    let head = repo.find_reference("HEAD")?;
    let symbolic = head
        .symbolic_target()
        .ok_or(Error::Generic("no symbolic target"))?;

    let mut parts = symbolic.split('/');

    Ok(parts
        .nth(2)
        .ok_or(Error::Generic(
            "symbolic target name should be on format 'refs/heads/main'",
        ))?
        .to_owned())
}
pub trait RepoExt {
    fn commit(
        &self,
        signature: &git2::Signature,
        message: &str,
        tree: &git2::Tree,
        parents: &[&git2::Commit],
        crypto: &(dyn Crypto + Send),
        passphrase_provider: Option<PassphraseProvider>,
    ) -> Result<Oid>;
    fn find_last_commit(&self) -> Result<git2::Commit>;
    fn should_sign(&self) -> bool;
    fn match_with_parent(
        &self,
        commit: &git2::Commit,
        parent: &git2::Commit,
        opts: &mut git2::DiffOptions,
    ) -> Result<bool>;
    fn add_file(
        &self,
        paths: &[PathBuf],
        message: &str,
        crypto: &(dyn Crypto + Send),
        passphrase_provider: Option<PassphraseProvider>,
        should_commit: bool,
    ) -> Result<Oid>;
    fn read_git_meta_data(
        &self,
        base: &Path,
        path: &Path,
        store: &PasswordStore,
    ) -> (
        Result<DateTime<Local>>,
        Result<String>,
        Result<SignatureStatus>,
    );
    fn init_git_repo(base: &Path) -> Result<git2::Repository>;
    fn append_entry_if_matched(
        &self,
        target: &Path,
        found: &Path,
        commit: &git2::Commit,
        entry_list: &mut Vec<PasswordEntry>,
        oid: &git2::Oid,
        store: &PasswordStore,
    ) -> bool;
    fn find_origin(&self) -> Result<(git2::Remote, String)>;
    fn verify_git_signature(&self, id: &Oid, store: &PasswordStore) -> Result<SignatureStatus>;
    fn remove_file(
        &self,
        paths: &[PathBuf],
        crypto: &(dyn Crypto + Send),
        message: &str,
        // passphrase: Option<&str>,
        passphrase_provider: Option<PassphraseProvider>,
        should_commit: bool,
    ) -> Result<Oid>;
    fn move_file(
        &self,
        old_name: &Path,
        new_name: &Path,
        crypto: &(dyn Crypto + Send),
        message: &str,
        passphrase_provider: Option<PassphraseProvider>,
        // passphrase: Option<&str>,
        should_commit: bool,
    ) -> Result<git2::Oid>;
    fn push(&self, userm_home: Option<PathBuf>) -> Result<()>;
    fn pull(&self, user_home: Option<PathBuf>) -> Result<()>;
}
impl RepoExt for git2::Repository {
    fn push(&self, user_home: Option<PathBuf>) -> Result<()> {
        let mut ref_status = None;
        let (mut origin, branch_name) = self.find_origin()?;
        let res = {
            let mut callbacks = git2::RemoteCallbacks::new();
            let mut tried_ssh_key = false;
            callbacks.credentials(|_url, username, allowed| {
                cred(&mut tried_ssh_key, _url, username, allowed)
            });
            callbacks.certificate_check(|cert, host| certificate_check(cert, host, &user_home));
            callbacks.push_update_reference(|_refname, status| {
                ref_status = status.map(std::borrow::ToOwned::to_owned);
                Ok(())
            });
            let mut opts = git2::PushOptions::new();
            opts.remote_callbacks(callbacks);
            origin.push(&[format!("refs/heads/{branch_name}")], Some(&mut opts))
        };
        match res {
            Ok(()) if ref_status.is_none() => Ok(()),
            Ok(()) => Err(Error::GenericDyn(format!(
                "failed to push a ref: {ref_status:?}",
            ))),
            Err(e) => Err(Error::GenericDyn(format!("failure to push: {e}"))),
        }
    }
    fn pull(&self, user_home: Option<PathBuf>) -> Result<()> {
        let (mut origin, branch_name) = self.find_origin()?;

        let mut cb = git2::RemoteCallbacks::new();
        let mut tried_ssh_key = false;
        cb.credentials(|_url, username, allowed| cred(&mut tried_ssh_key, _url, username, allowed));

        cb.certificate_check(|cert, host| certificate_check(cert, host, &user_home));

        let mut opts = git2::FetchOptions::new();
        opts.remote_callbacks(cb);
        origin.fetch(&[branch_name], Some(&mut opts), None)?;

        let remote_oid = self.refname_to_id("FETCH_HEAD")?;
        let head_oid = self.refname_to_id("HEAD")?;

        let (_, behind) = self.graph_ahead_behind(head_oid, remote_oid)?;

        if behind == 0 {
            return Ok(());
        }

        let remote_annotated_commit = self.find_annotated_commit(remote_oid)?;
        let remote_commit = self.find_commit(remote_oid)?;
        self.merge(&[&remote_annotated_commit], None, None)?;

        //commit it
        let mut index = self.index()?;
        let oid = index.write_tree()?;
        let signature = self.signature()?;
        let parent_commit = self.find_last_commit()?;
        let tree = self.find_tree(oid)?;
        let message = "pull and merge by rpass";
        let _commit = self.commit(
            Some("HEAD"), //  point HEAD to our new commit
            &signature,   // author
            &signature,   // committer
            message,      // commit message
            &tree,        // tree
            &[&parent_commit, &remote_commit],
        )?; // parents

        self.cleanup_state()?;
        Ok(())
    }
    /// Move a file to a new place in the store, and commit if needed
    fn move_file(
        &self,
        old_name: &Path,
        new_name: &Path,
        crypto: &(dyn Crypto + Send),
        message: &str,
        passphrase_provider: Option<PassphraseProvider>,
        should_commit: bool,
    ) -> Result<git2::Oid> {
        let mut index = self.index()?;
        index.remove_path(old_name)?;
        index.add_path(new_name)?;
        index.write()?;
        let oid = index.write_tree()?;
        if should_commit {
            let signature = self.signature()?;
            let parent_commit_res = self.find_last_commit();
            let mut parents = vec![];
            let parent_commit;
            if parent_commit_res.is_ok() {
                parent_commit = parent_commit_res?;
                parents.push(&parent_commit);
            }
            let tree = self.find_tree(oid)?;

            let oid = RepoExt::commit(
                self,
                &signature,
                message,
                &tree,
                &parents,
                crypto,
                passphrase_provider,
            )?;

            Ok(oid)
        } else {
            Ok(oid)
        }
    }
    /// Remove a file from the store, and commit if needed
    fn remove_file(
        &self,
        paths: &[PathBuf],
        crypto: &(dyn Crypto + Send),
        message: &str,
        passphrase_provider: Option<PassphraseProvider>,
        should_commit: bool,
    ) -> Result<git2::Oid> {
        let mut index = self.index()?;
        for path in paths {
            index.remove_path(path)?;
            index.write()?;
        }
        let oid = index.write_tree()?;
        if should_commit {
            let signature = self.signature()?;
            let parent_commit_res = self.find_last_commit();
            let mut parents = vec![];
            let parent_commit;
            if parent_commit_res.is_ok() {
                parent_commit = parent_commit_res?;
                parents.push(&parent_commit);
            }
            index.write_tree()?;
            let tree = self.find_tree(oid)?;

            let oid = RepoExt::commit(
                self,
                &signature,
                message,
                &tree,
                &parents,
                crypto,
                passphrase_provider,
            )?;
            Ok(oid)
        } else {
            Ok(oid)
        }
    }
    fn find_origin(&self) -> Result<(git2::Remote, String)> {
        for branch in self.branches(Some(git2::BranchType::Local))? {
            let b = branch?.0;
            if b.is_head() {
                let upstream_name_buf = self.branch_upstream_remote(&format!(
                    "refs/heads/{}",
                    &b.name()?.ok_or("no branch name")?
                ))?;
                let upstream_name = upstream_name_buf
                    .as_str()
                    .ok_or("Can't convert to string")?;
                let origin = self.find_remote(upstream_name)?;
                return Ok((origin, b.name()?.ok_or("no branch name")?.to_owned()));
            }
        }

        Err(Error::Generic("no remotes configured"))
    }
    fn commit(
        &self,
        signature: &git2::Signature,
        message: &str,
        tree: &git2::Tree,
        parents: &[&git2::Commit],
        crypto: &(dyn Crypto + Send),
        passphrase_provider: Option<PassphraseProvider>, // passphrase: Option<&str>,
    ) -> Result<git2::Oid> {
        if self.should_sign() {
            let commit_buf = self.commit_create_buffer(
                signature, // author
                signature, // committer
                message,   // commit message
                tree,      // tree
                parents,   // parents
            )?;

            let commit_as_str = str::from_utf8(&commit_buf)?;
            let sig = crypto.sign_string(
                commit_as_str,
                &[],
                &FindSigningFingerprintStrategy::GIT,
                passphrase_provider,
                // passphrase.map(|s| s.to_owned()),
                self.config().ok(),
            )?;

            let commit = self.commit_signed(commit_as_str, &sig, Some("gpgsig"))?;

            if let Ok(mut head) = self.head() {
                head.set_target(commit, "added a signed commit using rpass")?;
            } else {
                self.branch(&git_branch_name(self)?, &self.find_commit(commit)?, false)?;
            }

            Ok(commit)
        } else {
            let commit = self.commit(
                Some("HEAD"), //  point HEAD to our new commit
                signature,    // author
                signature,    // committer
                message,      // commit message
                tree,         // tree
                parents,      // parents
            )?;

            Ok(commit)
        }
    }

    fn find_last_commit(&self) -> Result<git2::Commit> {
        let obj = self.head()?.resolve()?.peel(git2::ObjectType::Commit)?;
        obj.into_commit()
            .map_err(|_| Error::Generic("Couldn't find commit"))
    }

    /// Returns if a git commit should be gpg signed or not.
    fn should_sign(&self) -> bool {
        self.config().map_or(false, |config| {
            config.get_bool("commit.gpgsign").unwrap_or(true)
        })
    }

    /// returns true if the diff between the two commit's contains the path that the `DiffOptions`
    /// have been prepared with
    fn match_with_parent(
        &self,
        commit: &git2::Commit,
        parent: &git2::Commit,
        opts: &mut git2::DiffOptions,
    ) -> Result<bool> {
        let a = parent.tree()?;
        let b = commit.tree()?;
        let diff = self.diff_tree_to_tree(Some(&a), Some(&b), Some(opts))?;
        Ok(diff.deltas().len() > 0)
    }

    /// Add a file to the store, and commit if needed
    fn add_file(
        &self,
        paths: &[PathBuf],
        message: &str,
        crypto: &(dyn Crypto + Send),
        passphrase_provider: Option<PassphraseProvider>,
        should_commit: bool,
    ) -> Result<git2::Oid> {
        let mut index = self.index()?;
        for path in paths {
            index.add_path(path)?;
            index.write()?;
        }

        let mut parents = vec![];
        let parent_commit;
        if let Ok(pc) = self.find_last_commit() {
            parent_commit = pc;
            parents.push(&parent_commit);
        }
        let oid = index.write_tree()?;
        if !should_commit {
            Ok(oid)
        } else {
            let signature = self.signature()?;
            let tree = self.find_tree(oid)?;

            let oid = RepoExt::commit(
                self,
                &signature,
                message,
                &tree,
                &parents,
                crypto,
                passphrase_provider,
            )?;
            Ok(oid)
        }
    }
    fn read_git_meta_data(
        &self,
        base: &Path,
        path: &Path,
        store: &PasswordStore,
    ) -> (
        Result<DateTime<Local>>,
        Result<String>,
        Result<SignatureStatus>,
    ) {
        let path_res = path.strip_prefix(base);
        if let Err(e) = path_res {
            return triple(&e);
        }

        let blame_res = self.blame_file(path_res.unwrap(), None);
        if let Err(e) = blame_res {
            return triple(&e);
        }
        let blame = blame_res.unwrap();
        let id_res = blame
            .get_line(1)
            .ok_or(Error::Generic("no git history found"));

        if let Err(e) = id_res {
            return triple(&e);
        }
        let id = id_res.unwrap().orig_commit_id();

        let commit_res = self.find_commit(id);
        if let Err(e) = commit_res {
            return triple(&e);
        }
        let commit = commit_res.unwrap();

        let time = commit.time();
        let time_return = to_result(Local.timestamp_opt(time.seconds(), 0));

        let name_return = name_from_commit(&commit);

        let signature_return = self.verify_git_signature(&id, store);

        (time_return, name_return, signature_return)
    }
    fn verify_git_signature(&self, id: &Oid, store: &PasswordStore) -> Result<SignatureStatus> {
        let (signature, signed_data) = self.extract_signature(id, Some("gpgsig"))?;

        let signature_str = str::from_utf8(&signature)?.to_owned();
        let signed_data_str = str::from_utf8(&signed_data)?.to_owned();

        if store.get_valid_gpg_signing_keys().is_empty() {
            return Err(Error::Generic(
                "signature not checked as PASSWORD_STORE_SIGNING_KEY is not configured",
            ));
        }
        match store.get_crypto().verify_sign(&signed_data_str.into_bytes(), &signature_str.into_bytes(), store.get_valid_gpg_signing_keys()) {
        Ok(r) => Ok(r),
        Err(VerificationError::InfrastructureError(message)) => Err(Error::GenericDyn(message)),
        Err(VerificationError::SignatureFromWrongRecipient) => Err(Error::Generic("the commit wasn't signed by one of the keys specified in the environmental variable PASSWORD_STORE_SIGNING_KEY")),
        Err(VerificationError::BadSignature) => Err(Error::Generic("Bad signature for commit")),
        Err(VerificationError::MissingSignatures) => Err(Error::Generic("Missing signature for commit")),
        Err(VerificationError::TooManySignatures) => Err(Error::Generic("If a git commit contains more than one signature, something is fishy")),
        }
    }
    /// Initialize a git repository for the store.
    /// # Errors
    /// Returns an `Err` if the git init fails
    fn init_git_repo(base: &Path) -> Result<Self> {
        Ok(git2::Repository::init(base)?)
    }
    fn append_entry_if_matched(
        &self,
        target: &Path,
        found: &Path,
        commit: &git2::Commit,
        entries: &mut Vec<PasswordEntry>,
        oid: &git2::Oid,
        store: &PasswordStore,
    ) -> bool {
        if *target == *found {
            let time = commit.time();
            let time_return = to_result(Local.timestamp_opt(time.seconds(), 0));

            let name_return = name_from_commit(commit);

            let signature_return = self.verify_git_signature(oid, store);

            entries.push(PasswordEntry::new(
                &store.get_store_path(),
                target,
                time_return,
                name_return,
                signature_return,
                RepositoryStatus::InRepo,
            ));
            return false;
        }
        true
    }
}

fn triple<T: Display>(
    e: &T,
) -> (
    Result<DateTime<Local>>,
    Result<String>,
    Result<SignatureStatus>,
) {
    (
        Err(Error::GenericDyn(format!("{e}"))),
        Err(Error::GenericDyn(format!("{e}"))),
        Err(Error::GenericDyn(format!("{e}"))),
    )
}

fn cred(
    tried_sshkey: &mut bool,
    _url: &str,
    username: Option<&str>,
    allowed: git2::CredentialType,
) -> std::result::Result<git2::Cred, git2::Error> {
    let sys_username = whoami::username();
    let user: &str = username.map_or(&sys_username, |name| name);

    if allowed.contains(git2::CredentialType::USERNAME) {
        return git2::Cred::username(user);
    }

    if *tried_sshkey {
        return Err(git2::Error::from_str("no authentication available"));
    }
    *tried_sshkey = true;

    git2::Cred::ssh_key_from_agent(user)
}

/// Find the name of the committer, or an error message
fn name_from_commit(commit: &git2::Commit) -> Result<String> {
    commit
        .committer()
        .name()
        .map_or(Err(Error::Generic("missing committer name")), |s| {
            Ok(s.to_owned())
        })
}

/// The git2 callback used to validate a certificate (only ssh known hosts are validated).
pub fn certificate_check(
    cert: &Cert<'_>,
    host: &str,
    home: &Option<PathBuf>,
) -> std::result::Result<CertificateCheckStatus, git2::Error> {
    let port: Option<u16> = Some(22);
    let Some(host_key) = cert.as_hostkey() else {
        // Return passthrough for TLS X509 certificates to use whatever validation
        // was done in git2.
        return Ok(CertificateCheckStatus::CertificatePassthrough);
    };
    // If a nonstandard port is in use, check for that first.
    // The fallback to check without a port is handled in the HostKeyNotFound handler.
    let host_maybe_port = match port {
        Some(port) if port != 22 => format!("[{host}]:{port}"),
        _ => host.to_string(),
    };
    // The error message must be constructed as a string to pass through the libgit2 C API.
    let err_msg = match check_ssh_known_hosts(host_key, &host_maybe_port, home) {
        Ok(()) => {
            return Ok(CertificateCheckStatus::CertificateOk);
        }
        Err(KnownHostError::CheckError(e)) => {
            format!("error: failed to validate host key:\n{e:#}")
        }
        Err(KnownHostError::HostKeyNotFound {
            hostname,
            key_type,
            remote_host_key,
            remote_fingerprint,
            other_hosts,
        }) => {
            // Try checking without the port.
            if port.is_some()
                && !matches!(port, Some(22))
                && check_ssh_known_hosts(host_key, host, home).is_ok()
            {
                return Ok(CertificateCheckStatus::CertificateOk);
            }
            let key_type_short_name = key_type.short_name();
            let key_type_name = key_type.name();
            let known_hosts_location = user_known_host_location_to_add(home);
            let other_hosts_message = if other_hosts.is_empty() {
                String::new()
            } else {
                let mut msg = String::from(
                    "Note: This host key was found, \
                    but is associated with a different host:\n",
                );
                for known_host in other_hosts {
                    let loc = match known_host.location {
                        KnownHostLocation::File { path, lineno } => {
                            format!("{} line {lineno}", path.display())
                        }
                    };
                    writeln!(msg, "    {loc}: {}", known_host.patterns).unwrap();
                }
                msg
            };
            format!("error: unknown SSH host key\n\
                The SSH host key for `{hostname}` is not known and cannot be validated.\n\
                \n\
                To resolve this issue, add the host key to {known_hosts_location}\n\
                \n\
                The key to add is:\n\
                \n\
                {hostname} {key_type_name} {remote_host_key}\n\
                \n\
                The {key_type_short_name} key fingerprint is: SHA256:{remote_fingerprint}\n\
                This fingerprint should be validated with the server administrator that it is correct.\n\
                {other_hosts_message}\n\
                See https://doc.rust-lang.org/nightly/cargo/appendix/git-authentication.html#ssh-known-hosts \
                for more information.\n\
                ")
        }
        Err(KnownHostError::HostKeyHasChanged {
            hostname,
            key_type,
            old_known_host,
            remote_host_key,
            remote_fingerprint,
        }) => {
            let key_type_short_name = key_type.short_name();
            let key_type_name = key_type.name();
            let known_hosts_location = user_known_host_location_to_add(home);
            let old_key_resolution = match old_known_host.location {
                KnownHostLocation::File { path, lineno } => {
                    let old_key_location = path.display();
                    format!(
                        "removing the old {key_type_name} key for `{hostname}` \
                        located at {old_key_location} line {lineno}, \
                        and adding the new key to {known_hosts_location}",
                    )
                }
            };
            format!("error: SSH host key has changed for `{hostname}`\n\
                *********************************\n\
                * WARNING: HOST KEY HAS CHANGED *\n\
                *********************************\n\
                This may be caused by a man-in-the-middle attack, or the \
                server may have changed its host key.\n\
                \n\
                The {key_type_short_name} fingerprint for the key from the remote host is:\n\
                    SHA256:{remote_fingerprint}\n\
                \n\
                You are strongly encouraged to contact the server \
                administrator for `{hostname}` to verify that this new key is \
                correct.\n\
                \n\
                If you can verify that the server has a new key, you can \
                resolve this error by {old_key_resolution}\n\
                \n\
                The key provided by the remote host is:\n\
                \n\
                {hostname} {key_type_name} {remote_host_key}\n\
                \n\
                See https://doc.rust-lang.org/nightly/cargo/appendix/git-authentication.html#ssh-known-hosts \
                for more information.\n\
                ")
        }
    };
    Err(git2::Error::new(
        git2::ErrorCode::GenericError,
        git2::ErrorClass::Callback,
        err_msg,
    ))
}

enum KnownHostError {
    /// Some general error happened while validating the known hosts.
    CheckError(anyhow::Error),
    /// The host key was not found.
    HostKeyNotFound {
        hostname: String,
        key_type: git2::cert::SshHostKeyType,
        remote_host_key: String,
        remote_fingerprint: String,
        other_hosts: Vec<KnownHost>,
    },
    /// The host key was found, but does not match the remote's key.
    HostKeyHasChanged {
        hostname: String,
        key_type: git2::cert::SshHostKeyType,
        old_known_host: KnownHost,
        remote_host_key: String,
        remote_fingerprint: String,
    },
}

impl From<anyhow::Error> for KnownHostError {
    fn from(err: anyhow::Error) -> KnownHostError {
        KnownHostError::CheckError(err)
    }
}

/// The location where a host key was located.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum KnownHostLocation {
    /// Loaded from a file from disk.
    File { path: PathBuf, lineno: u32 },
}

/// A single known host entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct KnownHost {
    location: KnownHostLocation,
    /// The hostname. May be comma separated to match multiple hosts.
    patterns: String,
    key_type: String,
    key: Vec<u8>,
}

impl KnownHost {
    /// Returns whether or not the given host matches this known host entry.
    fn host_matches(&self, host: &str) -> bool {
        let mut match_found = false;
        let host = host.to_lowercase();
        if let Some(hashed) = self.patterns.strip_prefix(HASH_HOSTNAME_PREFIX) {
            return hashed_hostname_matches(&host, hashed);
        }
        for pattern in self.patterns.split(',') {
            let pattern = pattern.to_lowercase();
            // FIXME: support * and ? wildcards
            if let Some(pattern) = pattern.strip_prefix('!') {
                if pattern == host {
                    return false;
                }
            } else {
                match_found = pattern == host;
            }
        }
        match_found
    }
}

fn hashed_hostname_matches(host: &str, hashed: &str) -> bool {
    let Some((b64_salt, b64_host)) = hashed.split_once('|') else {
        return false;
    };
    let Ok(salt) = STANDARD.decode(b64_salt) else {
        return false;
    };
    let Ok(hashed_host) = STANDARD.decode(b64_host) else {
        return false;
    };
    let Ok(mut mac) = hmac::Hmac::<sha1::Sha1>::new_from_slice(&salt) else {
        return false;
    };
    mac.update(host.as_bytes());
    let result = mac.finalize().into_bytes();
    hashed_host == result[..]
}

/// Checks if the given host/host key pair is known.
#[allow(clippy::result_large_err)]
fn check_ssh_known_hosts(
    cert_host_key: &git2::cert::CertHostkey<'_>,
    host: &str,
    home: &Option<PathBuf>,
) -> std::result::Result<(), KnownHostError> {
    let Some(remote_host_key) = cert_host_key.hostkey() else {
        return Err(anyhow::format_err!("remote host key is not available").into());
    };
    let remote_key_type = cert_host_key.hostkey_type().unwrap();
    // `changed_key` keeps track of any entries where the key has changed.
    let mut changed_key = None;
    // `other_hosts` keeps track of any entries that have an identical key,
    // but a different hostname.
    let mut other_hosts = Vec::new();

    // Collect all the known host entries from disk.
    let mut known_hosts = Vec::new();
    for path in known_host_files(home) {
        if !path.exists() {
            continue;
        }
        let hosts = load_hostfile(&path)?;
        known_hosts.extend(hosts);
    }

    for known_host in known_hosts {
        // The key type from libgit2 needs to match the key type from the host file.
        if known_host.key_type != remote_key_type.name() {
            continue;
        }
        let key_matches = known_host.key == remote_host_key;
        if !known_host.host_matches(host) {
            // `name` can be None for hashed hostnames (which libgit2 does not expose).
            if key_matches {
                other_hosts.push(known_host.clone());
            }
            continue;
        }
        if key_matches {
            return Ok(());
        }
        // The host and key type matched, but the key itself did not.
        // This indicates the key has changed.
        // This is only reported as an error if no subsequent lines have a
        // correct key.
        changed_key = Some(known_host.clone());
    }
    // Older versions of OpenSSH (before 6.8, March 2015) showed MD5
    // fingerprints (see FingerprintHash ssh config option). Here we only
    // support SHA256.
    let remote_fingerprint = {
        let mut hasher = Sha256::new();
        hasher.update(remote_host_key);
        hasher.finalize()
    };
    let remote_fingerprint = STANDARD_NO_PAD.encode(remote_fingerprint);
    let remote_host_key = STANDARD.encode(remote_host_key);
    // FIXME: Ideally the error message should include the IP address of the
    // remote host (to help the user validate that they are connecting to the
    // host they were expecting to). However, I don't see a way to obtain that
    // information from libgit2.
    match changed_key {
        Some(old_known_host) => Err(KnownHostError::HostKeyHasChanged {
            hostname: host.to_string(),
            key_type: remote_key_type,
            old_known_host,
            remote_host_key,
            remote_fingerprint,
        }),
        None => Err(KnownHostError::HostKeyNotFound {
            hostname: host.to_string(),
            key_type: remote_key_type,
            remote_host_key,
            remote_fingerprint,
            other_hosts,
        }),
    }
}

/// Returns a list of files to try loading OpenSSH-formatted known hosts.
fn known_host_files(home: &Option<PathBuf>) -> Vec<PathBuf> {
    let mut result = Vec::new();
    result.push(PathBuf::from("/etc/ssh/ssh_known_hosts"));
    result.extend(user_known_host_location(home));
    result
}

/// The location to display in an error message instructing the user where to
/// add the new key.
fn user_known_host_location_to_add(home: &Option<PathBuf>) -> String {
    // Note that we don't bother with the legacy known_hosts2 files.
    match user_known_host_location(home) {
        Some(path) => path.to_str().expect("utf-8 home").to_string(),
        None => "~/.ssh/known_hosts".to_string(),
    }
}

/// The location of the user's known_hosts file.
fn user_known_host_location(home: &Option<PathBuf>) -> Option<PathBuf> {
    // NOTE: This is a potentially inaccurate prediction of what the user
    // actually wants. The actual location depends on several factors:
    //
    // - Windows OpenSSH Powershell version: I believe this looks up the home
    //   directory via ProfileImagePath in the registry, falling back to
    //   `GetWindowsDirectoryW` if that fails.
    // - OpenSSH Portable (under msys): This is very complicated. I got lost
    //   after following it through some ldap/active directory stuff.
    // - OpenSSH (most unix platforms): Uses `pw->pw_dir` from `getpwuid()`.
    //
    // This doesn't do anything close to that. home_dir's behavior is:
    // - Windows: $USERPROFILE, or SHGetFolderPathW()
    // - Unix: $HOME, or getpwuid_r()
    //
    // Since there is a mismatch here, the location returned here might be
    // different than what the user's `ssh` CLI command uses. We may want to
    // consider trying to align it better.
    home.clone().map(|mut home| {
        home.push(".ssh");
        home.push("known_hosts");
        home
    })
}

/// Loads an OpenSSH known_hosts file.
fn load_hostfile(path: &Path) -> std::result::Result<Vec<KnownHost>, anyhow::Error> {
    let contents = String::from_utf8(std::fs::read(path)?)?;
    let entries = contents
        .lines()
        .enumerate()
        .filter_map(|(lineno, line)| {
            let location = KnownHostLocation::File {
                path: path.to_path_buf(),
                lineno: lineno as u32 + 1,
            };
            parse_known_hosts_line(line, location)
        })
        .collect();
    Ok(entries)
}

fn parse_known_hosts_line(line: &str, location: KnownHostLocation) -> Option<KnownHost> {
    let line = line.trim();
    // FIXME: @revoked and @cert-authority is currently not supported.
    if line.is_empty() || line.starts_with(['#', '@']) {
        return None;
    }
    let mut parts = line.split([' ', '\t']).filter(|s| !s.is_empty());
    let Some(patterns) = parts.next() else {
        return None;
    };
    let Some(key_type) = parts.next() else {
        return None;
    };
    let Some(key) = parts.next() else { return None };
    let Ok(key) = STANDARD.decode(key) else {
        return None;
    };
    Some(KnownHost {
        location,
        patterns: patterns.to_string(),
        key_type: key_type.to_string(),
        key,
    })
}

#[cfg(test)]
#[path = "tests/git.rs"]
mod git_tests;
