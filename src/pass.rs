/*  Rpass - a simple password manager using GPG and git, forked from cortex/ripasso
    Copyright (C) 2019-2020 Junhyeok Jang

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 3 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
use super::pass;
use crate::interface::DataFieldType;
use git2::Repository;
use log::*;
use serde::{de::Error as serde_err, ser::SerializeStruct, Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Debug,
    fs::{self, remove_dir_all},
    fs::{create_dir_all, File},
    io::prelude::*,
    path::{Path, PathBuf},
    str::{self, FromStr},
    sync::{Arc, Mutex},
};
use uuid::Uuid;

use chrono::prelude::*;
use totp_rs::TOTP;

use crate::{
    crypto::{Crypto, CryptoImpl, GpgMe, Handler, VerificationError},
    git::*,
    interface::UpdateLog,
};
pub use crate::{
    error::{to_result, Error, Result},
    signature::{
        parse_signing_keys, Comment, KeyRingStatus, OwnerTrustLevel, Recipient, SignatureStatus,
    },
};

pub static CUSTOM_FIELD_PREFIX: &str = "custom_";
/// Represents a complete password store directory
pub struct PasswordStore {
    /// Name given to the store in a config file
    name: String,
    /// The absolute path to the root directory of the password store
    root: PathBuf,
    /// A list of fingerprints of keys that are allowed to sign the .gpg-id file, obtained from the environmental
    /// variable `PASSWORD_STORE_SIGNING_KEY` or from the configuration file
    valid_gpg_signing_keys: Vec<[u8; 20]>,
    /// a list of password files with meta data
    pub passwords: Vec<PasswordEntry>,
    /// The gpg implementation
    crypto: Box<dyn Crypto + Send + Sync>,
    /// The home dir of the user, if it exists
    user_home: Option<PathBuf>,
    //id of key used to sign into the store (if any) - one of recipients in .gpg-id file
    login_recipient: Option<Recipient>,
}
impl Debug for PasswordStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordStore")
            .field("name", &self.name)
            .field("root", &self.root)
            .field("valid_gpg_signing_keys", &self.valid_gpg_signing_keys)
            .field("passwords", &self.passwords)
            .field("crypto", &self.crypto)
            .field("user_home", &self.user_home)
            .finish()
    }
}

impl Default for PasswordStore {
    fn default() -> Self {
        Self {
            name: "default".to_owned(),
            root: PathBuf::from("/tmp/"),
            valid_gpg_signing_keys: vec![],
            passwords: vec![],
            crypto: Box::new(GpgMe {}),
            user_home: None,
            login_recipient: None,
        }
    }
}

pub fn get_crypto(crypto_impl: &CryptoImpl) -> Box<dyn Crypto + Send + Sync> {
    match crypto_impl {
        CryptoImpl::GpgMe => Box::new(GpgMe {}),
    }
}

impl PasswordStore {
    /// Constructs a `PasswordStore` object. If `password_store_signing_key` is present,
    /// the function verifies that the .gpg-id file is signed correctly
    /// # Errors
    /// If the configuration or the on disk setup is incorrect
    pub fn new(
        store_name: &str,
        password_store_dir: &Option<PathBuf>,
        password_store_signing_key: &Option<String>,
        home: &Option<PathBuf>,
        crypto_impl: &CryptoImpl,
    ) -> Result<Self> {
        let pass_home = password_dir_raw(password_store_dir, home);
        if !pass_home.exists() {
            return Err(Error::Generic("failed to locate password directory"));
        }

        let crypto: Box<dyn Crypto + Send + Sync> = match crypto_impl {
            CryptoImpl::GpgMe => Box::new(GpgMe {}),
        };

        let signing_keys = parse_signing_keys(password_store_signing_key, crypto.as_ref())?;

        let store = Self {
            name: store_name.to_owned(),
            root: pass_home.canonicalize()?,
            valid_gpg_signing_keys: signing_keys,
            passwords: [].to_vec(),
            crypto,
            user_home: home.clone(),
            login_recipient: None,
        };

        if !store.valid_gpg_signing_keys.is_empty() {
            store.verify_gpg_id_files()?;
        }

        Ok(store)
    }

    pub fn set_login_recipient(&mut self, recipient: Option<Recipient>) {
        self.login_recipient = recipient;
    }
    pub fn get_login_recipient(&self) -> Option<&Recipient> {
        self.login_recipient.as_ref()
    }

    /// Creates a `PasswordStore`, including creating directories and initializing the .gpg-id file
    /// # Errors
    /// Returns an `Err` if the directory exists, no recipients are empty or a full fingerprint
    /// wasn't specified.
    pub fn create(
        store_name: &str,
        password_store_dir: &Option<PathBuf>,
        recipients: &[Recipient],
        valid_gpg_id_signers: &[Recipient],
        signer: &Option<Recipient>,
        home: &Option<PathBuf>,
        passphrase_provider: Option<Handler>,
    ) -> Result<Self> {
        let pass_home = password_dir_raw(password_store_dir, home);
        if pass_home.exists() {
            return Err(Error::Generic(
                "trying to create a pass store in an existing directory",
            ));
        }

        if recipients.is_empty() {
            return Err(Error::Generic(
                "password store must have at least one member",
            ));
        }
        for recipient in recipients {
            if recipient.key_id.len() != 40 && recipient.key_id.len() != 42 {
                return Err(Error::Generic(
                    "member specification wasn't a full pgp fingerprint",
                ));
            }
        }

        let crypto = Box::new(GpgMe {});

        let valid_signing_keys =
            {
                if valid_gpg_id_signers.len() > 0 {
                    let mut fingerprints = vec![];
                    for signer in valid_gpg_id_signers {
                        let raw_key_id = hex::decode(signer.key_id.clone())?;
                        fingerprints.push(raw_key_id.try_into().map_err(|_| {
                            Error::Generic("failed to parse key id into fingerprint")
                        })?);
                    }
                    fingerprints
                } else {
                    vec![]
                }
            };

        create_dir_all(&pass_home)?;
        let res = {
            let recipient_file_res = Recipient::write_recipients_file(
                recipients,
                &pass_home.join(".gpg-id"),
                &valid_signing_keys,
                crypto.as_ref(),
                passphrase_provider.clone(),
            );
            if let Err(e) = recipient_file_res {
                remove_dir_all(&pass_home)?;
                return Err(e);
            }
            let repo = Repository::init_git_repo(&pass_home)?;
            if let Ok(mut config) = repo.config() {
                if let Some(repo_signer) = signer {
                    let fpt = repo_signer.fingerprint.unwrap();
                    let fpt_str = hex::encode_upper(fpt);
                    config.set_str("user.name", &repo_signer.name)?;
                    config.set_str("user.email", &repo_signer.email)?;
                    config.set_str("user.signingkey", &fpt_str)?;
                } else {
                    config.set_bool("commit.gpgsign", false)?;
                }
            }

            let first_commit_res = {
                if valid_signing_keys.len() > 0 {
                    let mut passphrase_provider = passphrase_provider.clone();
                    if let Some(ref mut passphrase_provider) = passphrase_provider {
                        passphrase_provider.request = Some("to sign .gpg-id file".to_string());
                    }
                    repo.add_file(
                        &[PathBuf::from(".gpg-id"), PathBuf::from(".gpg-id.sig")],
                        "initial commit by Rpass",
                        crypto.as_ref(),
                        passphrase_provider,
                        true,
                    )
                } else {
                    repo.add_file(
                        &[PathBuf::from(".gpg-id")],
                        "initial commit by Rpass",
                        crypto.as_ref(),
                        passphrase_provider.clone(),
                        true,
                    )
                }
            };
            first_commit_res
        };
        if let Err(e) = res {
            remove_dir_all(&pass_home)?;
            Err(e)
        } else {
            let store = Self {
                name: store_name.to_owned(),
                root: pass_home.canonicalize()?,
                valid_gpg_signing_keys: valid_signing_keys,
                passwords: [].to_vec(),
                crypto,
                user_home: home.clone(),
                login_recipient: None,
            };
            Ok(store)
        }
    }
    pub fn remove_entry(&mut self, id: &str) -> pass::Result<PasswordEntry> {
        let id = if let Ok(uuid) = uuid::Uuid::parse_str(id) {
            uuid
        } else {
            return Err("Invalid UUID".into());
        };
        let passwords = &mut self.passwords;
        if let Some(idx) = passwords.iter().position(|p| p.id == id) {
            let matching = passwords.remove(idx);
            return Ok(matching);
        } else {
            return Err("No password entry found".into());
        }
    }
    pub fn get_entries(&self, user_dir: Option<&str>) -> pass::Result<Vec<PasswordEntry>> {
        let passwords = &self.passwords;
        if let Some(user_dir) = user_dir {
            fn normalized(s: &str) -> String {
                s.to_lowercase()
            }
            fn matches(s: &str, q: &str) -> bool {
                normalized(s).as_str() == normalized(q).as_str()
            }
            let matching = passwords.iter().filter(|p| {
                let file_name = p.id.to_string();
                //assume that the file name is the same as ID of the entry
                let name_with_user_dir = Path::new(&file_name);
                let entry_user_dir = name_with_user_dir.parent().map_or(name_with_user_dir, |v| {
                    if v == Path::new("") {
                        name_with_user_dir
                    } else {
                        v
                    }
                });
                matches(&user_dir, entry_user_dir.to_str().unwrap())
            });
            let res: Vec<PasswordEntry> = matching.cloned().collect();
            return Ok(res);
        } else {
            return Ok(passwords.clone());
        }
    }
    pub fn update_default_entry_fields(
        &self,
        id: &str,
        domain: Option<&str>,
        new_name: Option<&str>,
        password: Option<&str>,
        note: Option<&str>,
        custom_fields: Option<&serde_json::Map<String, serde_json::Value>>,
        passphrase_provider: Option<Handler>,
    ) -> pass::Result<Vec<UpdateLog>> {
        let id = id.to_string();
        let mut json = serde_json::Map::<String, serde_json::Value>::new();
        if let Some(new_name) = new_name {
            json.insert(
                "username".to_string(),
                serde_json::Value::String(new_name.to_string()),
            );
        }
        if let Some(domain) = domain {
            json.insert(
                "domain".to_string(),
                serde_json::Value::String(domain.to_string()),
            );
        }
        if let Some(note) = note {
            json.insert(
                "note".to_string(),
                serde_json::Value::String(note.to_string()),
            );
        }
        if let Some(password) = password {
            json.insert(
                "password".to_string(),
                serde_json::Value::String(password.to_string()),
            );
        }
        if let Some(custom_fields) = custom_fields {
            for (key, value) in custom_fields {
                json.insert(CUSTOM_FIELD_PREFIX.to_owned() + &key, value.to_owned());
            }
        }
        if json.is_empty() {
            return Err(pass::Error::Generic("Nothing to update"));
        } else {
        }
        return self.insert_into_entry(&id, json.into(), passphrase_provider);
    }
    pub fn insert_into_entry(
        &self,
        id: &str,
        content: serde_json::Value,
        passphrase_provider: Option<Handler>,
    ) -> pass::Result<Vec<UpdateLog>> {
        let entry = self.get_entry(&id)?;
        let secret = entry.secret(self, passphrase_provider.clone())?;
        let mut update_logs = Vec::<UpdateLog>::new();
        if let Ok(mut previous) = serde_json::from_str::<serde_json::Value>(&secret) {
            let entry_data = previous
                .as_object_mut()
                .ok_or(pass::Error::Generic("Failed to parse entry content"))?;
            for (key, value) in content
                .as_object()
                .ok_or(pass::Error::Generic("Failed to parse entry content"))?
            {
                if let Some(old) = entry_data.get(key).cloned() {
                    if &old != value {
                        update_logs.push(UpdateLog::new(
                            DataFieldType::from_str(key).unwrap(),
                            old,
                            value.clone(),
                        ));
                    }
                }
                entry_data.insert(key.to_string(), value.clone());
            }
            let serialized = &serde_json::to_string(entry_data).map_err(|serde_err| {
                pass::Error::GenericDyn(format!("Failed to serialize entry content: {}", serde_err))
            })?;
            if self
                .overwrite_entry_file(&id, serialized, passphrase_provider.clone())
                .is_ok()
            {
                Ok(update_logs)
            } else {
                Err(pass::Error::Generic("Failed to update entry content"))
            }
        } else {
            Err(pass::Error::Generic("Failed to parse entry content"))
        }
    }
    pub fn create_entry(
        &mut self,
        username: Option<&str>,
        password: Option<&str>,
        domain: Option<&str>,
        note: Option<&str>,
        custom_fields: Option<HashMap<String, serde_json::Value>>,
        passphrase_provider: Option<Handler>,
    ) -> pass::Result<PasswordEntry> {
        let id = uuid::Uuid::new_v4().to_string();
        let password = password.unwrap_or_default();
        let username = username.unwrap_or_default();
        let domain = domain.unwrap_or_default();
        if password.contains("otpauth://") {
            error!("It seems like you are trying to save a TOTP code to the password store. This will reduce your 2FA solution to just 1FA, do you want to proceed?");
            return Err(pass::Error::Generic(
                "It seems like you are trying to save a TOTP code to the password store. This will reduce your 2FA solution to just 1FA, do you want to proceed?",
            ));
        }
        let mut json = serde_json::Map::<String, serde_json::Value>::new();
        json.insert("username".to_string(), serde_json::Value::from(username));
        json.insert("password".to_string(), serde_json::Value::from(password));
        json.insert("domain".to_string(), serde_json::Value::from(domain));
        json.insert("note".to_string(), serde_json::Value::from(note.clone()));
        for (key, value) in custom_fields.unwrap_or_default() {
            json.insert(CUSTOM_FIELD_PREFIX.to_owned() + &key, value);
        }
        let content = serde_json::to_string(&json).map_err(|serde_err| {
            pass::Error::GenericDyn(format!("Failed to serialize entry content: {}", serde_err))
        })?;
        self.create_entry_file(id.as_ref(), content.as_ref(), passphrase_provider)
    }
    fn create_entry_file(
        &mut self,
        id: &str,
        json_string: &str,
        passphrase_provider: Option<Handler>,
    ) -> pass::Result<PasswordEntry> {
        let entry = self.new_password_file(id.as_ref(), json_string.as_ref(), passphrase_provider);
        entry
    }

    #[allow(dead_code)]
    pub fn update_entry_field(
        &mut self,
        id: &str,
        key: &str,
        value: &str,
        passphrase_provider: Option<Handler>,
        create_if_not_exists: bool,
    ) -> pass::Result<Option<String>> {
        let entry = self.get_entry(&id);
        if let Ok(entry) = entry {
            let secret = entry.secret(self, passphrase_provider.clone())?;
            if let Ok(mut content) = serde_json::from_str::<serde_json::Value>(&secret) {
                let existing = content.get(key);
                if let Some(existing) = existing {
                    if let Some(existing) = existing.as_str().map(|v| v.to_string()) {
                        content
                            .as_object_mut()
                            .ok_or(pass::Error::Generic("Failed to parse entry content"))?
                            .insert(
                                key.to_string(),
                                serde_json::Value::String(value.to_string()),
                            );
                        let content = serde_json::to_string(&content).map_err(|serde_err| {
                            pass::Error::GenericDyn(format!(
                                "Failed to serialize entry content: {}",
                                serde_err
                            ))
                        })?;
                        self.overwrite_entry_file(&id, &content, passphrase_provider.clone())?;
                        Ok(Some(existing))
                    } else {
                        Err(pass::Error::GenericDyn(format!("existing entry content is in wrong format. Value is not of String type. Existing value: {:?}",existing.to_string()).to_string()))
                    }
                } else {
                    content
                        .as_object_mut()
                        .ok_or(pass::Error::Generic("Failed to parse entry content"))?
                        .insert(
                            key.to_string(),
                            serde_json::Value::String(value.to_string()),
                        );
                    let content = serde_json::to_string(&content).map_err(|serde_err| {
                        pass::Error::GenericDyn(format!(
                            "Failed to serialize entry content: {}",
                            serde_err
                        ))
                    })?;
                    self.overwrite_entry_file(&id, &content, passphrase_provider.clone())?;
                    return Ok(None);
                }
            } else {
                Err(pass::Error::Generic("Failed to parse entry content"))
            }
        } else {
            if create_if_not_exists {
                let mut content = serde_json::Map::<String, serde_json::Value>::new();
                content.insert(
                    key.to_string(),
                    serde_json::Value::String(value.to_string()),
                );

                let content = serde_json::to_string(&content).map_err(|serde_err| {
                    pass::Error::GenericDyn(format!(
                        "Failed to serialize entry content: {}",
                        serde_err
                    ))
                })?;
                self.create_entry_file(id, &content, passphrase_provider)?;
                Ok(None)
            } else {
                Err(pass::Error::Generic("Failed to parse entry content"))
            }
        }
    }

    pub fn delete_entry(
        &mut self,
        id: &str,
        passphrase_provider: Option<Handler>,
    ) -> pass::Result<PasswordEntry> {
        let password_entry_opt = self.remove_entry(id);
        let password_entry = password_entry_opt?;
        password_entry
            .delete_file(self, passphrase_provider)
            .map(|_| password_entry)
    }
    pub fn get_entry(&self, id: &str) -> pass::Result<PasswordEntry> {
        let passwords = &self.passwords;
        fn normalized(s: &str) -> String {
            s.to_lowercase()
        }
        fn matches(s: &str, p: &str) -> bool {
            normalized(s).as_str() == normalized(p).as_str()
        }
        let matching = passwords
            .iter()
            .find(|p| matches(&p.id.to_string(), id))
            .cloned();
        return matching.ok_or(pass::Error::GenericDyn(format!(
            "No entry found for id: {}",
            id
        )));
    }

    pub fn overwrite_entry_file(
        &self,
        file_name: &str,
        content: &str,
        passphrase_provider: Option<Handler>,
    ) -> pass::Result<()> {
        let password_entry_opt = self.get_entry(file_name);
        let password_entry = password_entry_opt.map_err(|_e| {
            pass::Error::GenericDyn(format!(
                "entry file to overwrite not found. Passed file id: {file_name}"
            ))
        })?;
        let r = password_entry.update(content.to_string(), &self, passphrase_provider);
        if r.is_err() {
            error!("Failed to update password: {:?}", r.as_ref().unwrap_err());
        }
        return r;
    }
    pub fn get_stores(
        config: &config::Config,
        home: &Option<PathBuf>,
    ) -> pass::Result<Vec<PasswordStore>> {
        let mut final_stores: Vec<PasswordStore> = vec![];
        let stores_res = config.get("stores");
        if let Ok(stores) = stores_res {
            let stores: HashMap<String, config::Value> = stores;
            for (store_name, store) in stores.iter() {
                let store = store.clone().into_table()?;
                let password_store_dir_opt = store.get("path");
                let valid_signing_keys_opt = store.get("valid_signing_keys");
                if let Some(store_dir) = password_store_dir_opt {
                    let password_store_dir = Some(PathBuf::from(store_dir.clone().into_str()?));

                    let valid_signing_keys = match valid_signing_keys_opt {
                        Some(k) => match k.clone().into_str() {
                            Err(_) => None,
                            Ok(key) => {
                                if key == "-1" {
                                    None
                                } else {
                                    Some(key)
                                }
                            }
                        },
                        None => None,
                    };

                    let pgp_impl = match store.get("pgp") {
                        Some(pgp_str) => CryptoImpl::try_from(pgp_str.clone().into_str()?.as_str()),
                        None => Ok(CryptoImpl::GpgMe),
                    }?;

                    final_stores.push(PasswordStore::new(
                        store_name,
                        &password_store_dir,
                        &valid_signing_keys,
                        home,
                        &pgp_impl,
                    )?);
                }
            }
        } else if final_stores.is_empty() {
            return Err(pass::Error::Generic(
                "No password store found. Please create default store in '~/.password-store' first",
            ));
        }

        Ok(final_stores)
    }

    /// Returns the name of the store, configured to the configuration file
    pub fn get_name(&self) -> &String {
        &self.name
    }

    /// Returns a vec with the keys that are allowed to sign the .gpg-id file
    pub fn get_valid_gpg_signing_keys(&self) -> &Vec<[u8; 20]> {
        &self.valid_gpg_signing_keys
    }

    /// returns the path to the directory where the store is located.
    pub fn get_store_path(&self) -> PathBuf {
        self.root.clone()
    }

    pub fn get_user_home(&self) -> Option<PathBuf> {
        self.user_home.clone()
    }

    /// returns the crypto implementation for the store
    pub fn get_crypto(&self) -> &(dyn Crypto + Send + Sync) {
        &*self.crypto
    }

    pub fn repo(&self) -> Result<git2::Repository> {
        Ok(git2::Repository::open(&self.root)?)
    }

    fn verify_gpg_id_files(&self) -> Result<SignatureStatus> {
        let mut result = SignatureStatus::Good;
        for gpg_id_file in self.recipients_files()? {
            let mut gpg_id_sig_file = self.root.clone();
            gpg_id_sig_file.push(".gpg-id.sig");

            let gpg_id = fs::read(gpg_id_file)?;
            let gpg_id_sig =
                match fs::read(gpg_id_sig_file) {
                    Ok(c) => c,
                    Err(_) => return Err(Error::Generic(
                        "problem reading .gpg-id.sig, and strict signature checking was asked for",
                    )),
                };

            match self.crypto.verify_sign(&gpg_id, &gpg_id_sig, &self.valid_gpg_signing_keys) {
                Ok(r) => {
                    match r {
                        SignatureStatus::Good => {},
                        SignatureStatus::AlmostGood => result = SignatureStatus::AlmostGood,
                        SignatureStatus::Bad => return Ok(SignatureStatus::Bad)
                    }
                },
                Err(VerificationError::InfrastructureError(message)) => return Err(Error::GenericDyn(message)),
                Err(VerificationError::SignatureFromWrongRecipient) => return Err(Error::Generic("the .gpg-id file wasn't signed by one of the keys specified in the environmental variable PASSWORD_STORE_SIGNING_KEY")),
                Err(VerificationError::BadSignature) => return Err(Error::Generic("Bad signature for .gpg-id file")),
                Err(VerificationError::MissingSignatures) => return Err(Error::Generic("Missing signature for .gpg-id file, and PASSWORD_STORE_SIGNING_KEY specified")),
                Err(VerificationError::TooManySignatures) => return Err(Error::Generic("Signature for .gpg-id file contained more than one signature, something is fishy")),
            }
        }
        Ok(result)
    }

    fn verify_gpg_id_file_for_path(&self, path: &Path) -> Result<SignatureStatus> {
        let gpg_id_file = self.recipients_file_for_dir(path)?;
        let gpg_id_sig_file = {
            let mut sig = gpg_id_file.clone();
            sig.pop();
            sig.join(".gpg-id.sig")
        };

        let gpg_id = fs::read(gpg_id_file)?;
        let gpg_id_sig = match fs::read(gpg_id_sig_file) {
            Ok(c) => c,
            Err(_) => {
                return Err(Error::Generic(
                    "problem reading .gpg-id.sig, and strict signature checking was asked for",
                ))
            }
        };

        match self.crypto.verify_sign(&gpg_id, &gpg_id_sig, &self.valid_gpg_signing_keys) {
            Ok(r) => Ok(r),
            Err(VerificationError::InfrastructureError(message)) => Err(Error::GenericDyn(message)),
            Err(VerificationError::SignatureFromWrongRecipient) => Err(Error::Generic("the .gpg-id file wasn't signed by one of the keys specified in the environmental variable PASSWORD_STORE_SIGNING_KEY")),
            Err(VerificationError::BadSignature) => Err(Error::Generic("Bad signature for .gpg-id file")),
            Err(VerificationError::MissingSignatures) => Err(Error::Generic("Missing signature for .gpg-id file, and PASSWORD_STORE_SIGNING_KEY specified")),
            Err(VerificationError::TooManySignatures) => Err(Error::Generic("Signature for .gpg-id file contained more than one signature, something is fishy")),
        }
    }

    pub fn new_password_file(
        &mut self,
        path_end: &str,
        content: &str,
        passphrase_provider: Option<Handler>,
    ) -> Result<PasswordEntry> {
        let mut path = self.root.clone();

        let c_path = std::fs::canonicalize(path.as_path())?;

        let path_iter = &mut path_end.split('/').peekable();

        while let Some(p) = path_iter.next() {
            if path_iter.peek().is_some() {
                path.push(p);
                let c_file_res = std::fs::canonicalize(path.as_path());
                if let Ok(c_file) = c_file_res {
                    if !c_file.starts_with(c_path.as_path()) {
                        return Err(Error::Generic(
                            "trying to write outside of password store directory",
                        ));
                    }
                }
                if !path.exists() {
                    std::fs::create_dir(&path)?;
                }
            } else {
                path.push(format!("{p}.gpg"));
            }
        }

        if path.exists() {
            return Err(Error::Generic("file already exist"));
        }

        match self.new_password_file_internal(&path, path_end, content, passphrase_provider, true) {
            Ok(pe) => Ok(pe),
            Err(err) => {
                // try to remove the file we created, as cleanup
                let _ = std::fs::remove_file(path);

                // but always return the original error
                Err(err)
            }
        }
    }

    fn new_password_file_internal(
        &mut self,
        path: &Path,
        path_end: &str,
        content: &str,
        passphrase_provider: Option<Handler>,
        should_commit: bool,
    ) -> Result<PasswordEntry> {
        let mut file = File::create(path)?;

        if !self.valid_gpg_signing_keys.is_empty() {
            self.verify_gpg_id_files()?;
        }

        let recipients = self.recipients_for_path(path)?;
        let output = self.crypto.encrypt_string(content, &recipients)?;

        if let Err(why) = file.write_all(&output) {
            return Err(Error::from(why));
        }
        match self.repo() {
            Err(_) => {
                self.passwords.push(PasswordEntry::load_from_filesystem(
                    &self.root,
                    &append_extension(PathBuf::from(path_end), ".gpg"),
                ));
                Ok(PasswordEntry::load_from_filesystem(
                    &self.root,
                    &append_extension(PathBuf::from(path_end), ".gpg"),
                ))
            }
            Ok(repo) => {
                let message = format!("Add password for {path_end} using rpass");

                repo.add_file(
                    &[append_extension(PathBuf::from(path_end), ".gpg")],
                    &message,
                    self.crypto.as_ref(),
                    passphrase_provider,
                    should_commit,
                )?;

                self.passwords
                    .push(PasswordEntry::load_from_git(&self.root, path, &repo, self));

                Ok(PasswordEntry::load_from_git(&self.root, path, &repo, self))
            }
        }
    }

    /// loads the list of passwords from disk again
    /// # Errors
    /// Returns an error if any of the passwords contain non-utf8 bytes
    pub fn reload_password_list(&mut self) -> Result<()> {
        let mut new_passwords = self.all_passwords()?;

        self.passwords.clear();

        self.passwords.append(&mut new_passwords);

        Ok(())
    }

    /// checks if there is a user name configured in git
    pub fn has_configured_username(&self) -> bool {
        if self.repo().is_err() {
            return true;
        }

        match self.repo().unwrap().config() {
            Err(_) => false,
            Ok(config) => {
                let user_name = config.get_string("user.name");

                if user_name.is_err() {
                    return false;
                }
                true
            }
        }
    }

    /// Read the password store directory and return a list of all the password files.
    /// # Errors
    /// Returns an error if any of the passwords contain non-utf8 bytes
    pub fn all_passwords(&self) -> Result<Vec<PasswordEntry>> {
        let mut passwords = vec![];
        let repo = self.repo();

        // Not a git repository
        if repo.is_err() {
            let password_path_glob = self.root.join("**/*.gpg");
            let existing_iter = glob::glob(&password_path_glob.to_string_lossy())?;

            for existing_file in existing_iter {
                let relpath = existing_file?.strip_prefix(&self.root)?.to_path_buf();
                passwords.push(PasswordEntry::load_from_filesystem(&self.root, &relpath));
            }

            return Ok(passwords);
        }

        let repo = repo?;
        // First, collect all files we need to find the first commit for

        // if .gpg files are direct children of the root, add them
        let password_path_glob = self.root.join("*.gpg");
        let existing_iter = glob::glob(&password_path_glob.to_string_lossy())?;
        let mut files_to_find: Vec<PathBuf> = vec![];
        for existing_file in existing_iter {
            let existing_file = existing_file?;
            let file_to_find = existing_file.strip_prefix(&self.root)?;

            files_to_find.push(file_to_find.to_path_buf());
        }

        // if files are in subdirectories, add them if the subdirectory is not another password store
        let password_path_glob = self.root.join("*/*.gpg");
        let existing_iter = glob::glob(&password_path_glob.to_string_lossy())?;
        for existing_file in existing_iter {
            let existing_file = existing_file?;
            if let Some(parent) = existing_file.parent() {
                if parent.join(".git").exists() {
                    continue;
                }
            }
            let file_to_find = existing_file.strip_prefix(&self.root)?;

            files_to_find.push(file_to_find.to_path_buf());
        }

        if files_to_find.is_empty() {
            return Ok(vec![]);
        }

        // Walk through all commits in reverse order, if the commit contains
        // the file, mark it
        let mut walk = repo.revwalk()?;
        walk.push(repo.head()?.target().ok_or("missing Oid on head")?)?;
        let mut last_tree = repo
            .find_commit(repo.head()?.target().ok_or("missing Oid on head")?)?
            .tree()?;
        let mut last_commit = repo.head()?.peel_to_commit()?;
        for rev in walk {
            if rev.is_err() {
                continue;
            }
            let oid = rev?;

            let commit = repo.find_commit(oid)?;
            let tree = commit.tree()?;

            let diff = repo.diff_tree_to_tree(Some(&last_tree), Some(&tree), None)?;

            diff.foreach(
                &mut |delta: git2::DiffDelta, _f: f32| {
                    if let Some(found) = delta.new_file().path() {
                        files_to_find.retain(|target| {
                            repo.append_entry_if_matched(
                                target,
                                found,
                                &commit,
                                &mut passwords,
                                &oid,
                                self,
                            )
                        });
                    }
                    true
                },
                None,
                None,
                None,
            )?;

            last_tree = tree;
            last_commit = commit;
        }

        // When we have checked all the diffs, we also need to consider what
        // files was checked in to the first commit
        last_tree.walk(git2::TreeWalkMode::PreOrder, |path, entry| {
            if let Some(entry_name) = entry.name() {
                let found = Path::new(path).join(entry_name);
                files_to_find.retain(|target| {
                    repo.append_entry_if_matched(
                        target,
                        &found,
                        &last_commit,
                        &mut passwords,
                        &last_commit.id(),
                        self,
                    )
                });
            }
            git2::TreeWalkResult::Ok
        })?;

        // If there are any files we couldn't find, add them to the list anyway
        for not_found in files_to_find {
            passwords.push(PasswordEntry::new(
                &self.root,
                &not_found.clone(),
                Err(Error::Generic("")),
                Err(Error::Generic("")),
                Err(Error::Generic("")),
                RepositoryStatus::NotInRepo,
            ));
        }

        Ok(passwords)
    }

    /// Return a list of all the Recipients in the `$PASSWORD_STORE_DIR/.gpg-id` file.
    /// # Errors
    /// Returns an `Err` if the gpg_id file should be verified and it can't be
    pub fn all_recipients(&self) -> Result<Vec<Recipient>> {
        if !self.valid_gpg_signing_keys.is_empty() {
            self.verify_gpg_id_files()?;
        }

        let mut recipients = vec![];
        for file in self.recipients_files()? {
            for r in Recipient::all_recipients(&file, self.crypto.as_ref())? {
                if !recipients.contains(&r) {
                    recipients.push(r);
                }
            }
        }
        Ok(recipients)
    }

    /// Return a list of all the Recipients in the `.gpg-id` file that is the
    /// closest parent to `path`.
    /// # Errors
    /// Returns an `Err` if the gpg_id file should be verified and it can't be
    pub fn recipients_for_path(&self, path: &Path) -> Result<Vec<Recipient>> {
        if !self.valid_gpg_signing_keys.is_empty() {
            self.verify_gpg_id_file_for_path(path)?;
        }

        Recipient::all_recipients(&self.recipients_file_for_dir(path)?, self.crypto.as_ref())
    }

    fn recipients_file_for_dir(&self, path: &Path) -> Result<PathBuf> {
        let mut new_dir = std::fs::canonicalize(self.root.join(path))?;

        let root = std::fs::canonicalize(&self.root)?;

        if !new_dir.starts_with(&root) {
            return Err(Error::Generic("path traversal is not allowed"));
        }

        while new_dir.starts_with(&root) {
            let f = new_dir.join(".gpg-id");

            if f.exists() {
                return Ok(f);
            }
            new_dir.pop();
        }

        Err(Error::Generic("No .gpg-id file found in {path}"))
    }

    fn visit_dirs(dir: &Path, result: &mut Vec<PathBuf>) -> Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    //don't recurse into another store directory
                    if !path.join(".gpg-id").exists() {
                        Self::visit_dirs(&path, result)?;
                    }
                } else if entry.file_name() == ".gpg-id" {
                    result.push(entry.path());
                }
            }
        }
        Ok(())
    }

    fn recipients_files(&self) -> Result<Vec<PathBuf>> {
        let mut results = vec![];
        Self::visit_dirs(&self.root, &mut results)?;
        Ok(results)
    }

    fn remove_recipient_inner(
        &self,
        r: &Recipient,
        path: &Path,
        passphrase_provider: Option<Handler>,
    ) -> Result<()> {
        Recipient::remove_recipient_from_file(
            r,
            &self.recipients_file_for_dir(path)?,
            &self.root,
            &self.valid_gpg_signing_keys,
            self.crypto.as_ref(),
            passphrase_provider,
        )?;
        self.reencrypt_all_password_entries()
    }

    /// Removes a key from the .gpg-id file and re-encrypts all the passwords
    /// # Errors
    /// Returns an `Err` if the gpg_id file should be verified and it can't be or if the recipient is the last one.
    pub fn remove_recipient(
        &self,
        r: &Recipient,
        path: &Path,
        passphrase_provider: Option<Handler>,
    ) -> Result<()> {
        let gpg_id_file = &self.recipients_file_for_dir(path)?;
        let gpg_id_file_content = std::fs::read_to_string(gpg_id_file)?;

        let res = self.remove_recipient_inner(r, path, passphrase_provider);

        if res.is_err() {
            std::fs::write(gpg_id_file, gpg_id_file_content)?;
        }
        res
    }

    /// Adds a key to the .gpg-id file in the path directory and re-encrypts all the passwords
    /// # Errors
    /// Returns an `Err` if the gpg_id file should be verified and it can't be or there is some problem with
    /// the encryption.
    pub fn add_recipient(
        &mut self,
        r: &Recipient,
        path: &Path,
        config_path: &Path,
        passphrase_provider: Option<Handler>,
    ) -> Result<()> {
        if !self.crypto.is_key_in_keyring(r)? {
            self.crypto.pull_keys(&[r], config_path)?;
        }
        if !self.crypto.is_key_in_keyring(r)? {
            return Err(Error::Generic(
                "Key isn't in keyring and couldn't be downloaded from keyservers",
            ));
        }

        let dir = self.root.join(path);
        if !dir.exists() {
            return Err(Error::Generic("path doesn't exist"));
        }
        let dir = std::fs::canonicalize(self.root.join(path))?;
        let root = std::fs::canonicalize(&self.root)?;

        if !dir.starts_with(root) {
            return Err(Error::Generic("path traversal not allowed"));
        }
        if !dir.join(".gpg-id").exists() {
            std::fs::File::create(dir.join(".gpg-id"))?;
        }

        Recipient::add_recipient_to_file(
            r,
            &self.recipients_file_for_dir(path)?,
            &self.valid_gpg_signing_keys,
            self.crypto.as_ref(),
            passphrase_provider,
        )?;
        self.reencrypt_all_password_entries()
    }

    /// Reencrypt all the entries in the store, for example when a new collaborator is added
    /// to the team.
    /// # Errors
    /// Returns an `Err` if the gpg_id file should be verified and it can't be or there is some problem with
    /// the encryption.
    fn reencrypt_all_password_entries(&self) -> Result<()> {
        let mut names: Vec<PathBuf> = Vec::new();
        for entry in self.all_passwords()? {
            entry.update_internal(&entry.secret(self, None)?, self)?;
            names.push(append_extension(
                PathBuf::from(&entry.id.to_string()),
                ".gpg",
            ));
        }
        names.push(PathBuf::from(".gpg-id"));

        if self.repo().is_err() {
            return Ok(());
        }

        let keys = self
            .all_recipients()?
            .into_iter()
            .map(|s| format!("0x{}, ", s.key_id))
            .collect::<String>();
        let message = format!("Reencrypt password store with new GPG ids {keys}");

        self.add(&names, &message, None, true)?;
        Ok(())
    }
    pub fn try_passphrase(&mut self, passphrase_provider: Option<Handler>) -> Result<bool> {
        let res =
            self.crypto
                .try_passphrases(&self.all_recipients()?, passphrase_provider, Some(3));
        if let Ok(login_recipient_opt) = res {
            if let Some(login_recipient) = login_recipient_opt {
                self.set_login_recipient(Some(login_recipient));
                return Ok(true);
            } else {
                return Ok(false);
            }
        } else {
            return res.map(|_| false);
        }
    }

    /// Add a file to the store, and commit it to the supplied git repository.
    /// # Errors
    /// Returns an `Err` if there is any problems with git.
    pub fn add(
        &self,
        paths: &[PathBuf],
        message: &str,
        passphrase_provider: Option<Handler>,
        should_commit: bool,
    ) -> Result<git2::Oid> {
        let repo = self.repo();
        if repo.is_err() {
            return Err(Error::Generic("must have a repository"));
        }
        let repo = repo?;

        let mut index = repo.index()?;
        for path in paths {
            index.add_path(path)?;
        }
        let oid = index.write_tree()?;
        if should_commit {
            let signature = repo.signature()?;
            let parent_commit_res = repo.find_last_commit();
            let mut parents = vec![];
            let parent_commit;
            if parent_commit_res.is_ok() {
                parent_commit = parent_commit_res?;
                parents.push(&parent_commit);
            }
            let tree = repo.find_tree(oid)?;

            let oid = RepoExt::commit(
                &repo,
                &signature,
                message,
                &tree,
                &parents,
                self.crypto.as_ref(),
                passphrase_provider,
            )?;
            let obj = repo.find_object(oid, None)?;
            repo.reset(&obj, git2::ResetType::Hard, None)?;
            Ok(oid)
        } else {
            Ok(oid)
        }
    }

    ///Renames a password file to a new name
    ///returns the index in the password vec of the renamed `PasswordEntry`
    /// # Errors
    /// Returns an `Err` if the file is missing, or the target already exists.
    pub fn rename_file(
        &mut self,
        old_name: &str,
        new_name: &str,
        passphrase_provider: Option<Handler>,
    ) -> Result<usize> {
        if new_name.starts_with('/') || new_name.contains("..") {
            return Err(Error::Generic("directory traversal not allowed"));
        }

        let mut old_path = self.root.clone();
        old_path.push(PathBuf::from(old_name));
        let old_path = append_extension(old_path, ".gpg");
        let mut new_path = self.root.clone();
        new_path.push(PathBuf::from(new_name));
        let new_path = append_extension(new_path, ".gpg");

        if !old_path.exists() {
            return Err(Error::Generic("source file is missing"));
        }

        if new_path.exists() {
            return Err(Error::Generic("can't target file already exists"));
        }

        let mut new_path_dir = new_path.clone();
        new_path_dir.pop();
        fs::create_dir_all(&new_path_dir)?;

        let mut file = std::fs::File::create(&new_path)?;
        let secret = self
            .crypto
            .decrypt_string(&std::fs::read(&old_path)?, passphrase_provider.clone())?;
        let new_recipients = Recipient::all_recipients(
            &self.recipients_file_for_dir(&new_path)?,
            self.crypto.as_ref(),
        )?;
        file.write_all(&self.crypto.encrypt_string(&secret, &new_recipients)?)?;
        std::fs::remove_file(&old_path)?;

        if self.repo().is_ok() {
            let old_file_name = append_extension(PathBuf::from(old_name), ".gpg");
            let new_file_name = append_extension(PathBuf::from(new_name), ".gpg");
            self.repo()?.move_file(
                &old_file_name,
                &new_file_name,
                self.get_crypto(),
                "moved file",
                passphrase_provider,
                true,
            )?;
        }

        let passwords = &mut self.passwords;
        let mut index = usize::MAX;
        for (i, entry) in passwords.iter().enumerate() {
            if entry.id.to_string() == old_name {
                index = i;
            }
        }
        if index != usize::MAX {
            let old_entry = passwords.swap_remove(index);
            let relpath = new_path.strip_prefix(&self.root)?.to_path_buf();
            let new_entry = PasswordEntry::with_new_name(old_entry, &self.root, &relpath);
            passwords.push(new_entry);
        }

        Ok(passwords.len() - 1)
    }

    pub fn recipient_from(
        &self,
        key_id: &str,
        pre_comment: &[String],
        post_comment: Option<String>,
    ) -> Result<Recipient> {
        crate::signature::Recipient::from(key_id, pre_comment, post_comment, self.crypto.as_ref())
    }
    // delete store. if failed, return original one
    pub fn delete_store(self) -> std::result::Result<(), Self> {
        todo!()
    }
}

/// Return all `Recipient` across all different stores in the list.
/// # Errors
/// Returns an `Err` if there is a problem locking the mutex
pub fn all_recipients_from_stores(
    stores: Arc<Mutex<Vec<Arc<Mutex<PasswordStore>>>>>,
) -> Result<Vec<Recipient>> {
    let all_recipients: Vec<Recipient> = {
        let mut ar: HashMap<String, Recipient> = HashMap::new();
        let stores = stores
            .lock()
            .map_err(|_e| Error::Generic("problem locking the mutex"))?;
        #[allow(clippy::significant_drop_in_scrutinee)]
        for store in stores.iter() {
            let store = store
                .lock()
                .map_err(|_e| Error::Generic("problem locking the mutex"))?;
            #[allow(clippy::significant_drop_in_scrutinee)]
            for recipient in store.all_recipients()? {
                let key = match recipient.fingerprint.as_ref() {
                    None => recipient.key_id.clone(),
                    Some(fingerprint) => hex::encode_upper(fingerprint),
                };
                ar.insert(key, recipient);
            }
        }
        ar.into_values().collect()
    };

    Ok(all_recipients)
}

/// Describes one log line in the history of a file
#[non_exhaustive]
pub struct GitLogLine {
    /// the git commit message
    pub message: String,
    /// the timestamp of the commit
    pub commit_time: DateTime<Local>,
    /// the commit signature status
    pub signature_status: Option<SignatureStatus>,
}

impl GitLogLine {
    /// creates a `GitLogLine`
    pub fn new(
        message: String,
        commit_time: DateTime<Local>,
        signature_status: Option<SignatureStatus>,
    ) -> Self {
        Self {
            message,
            commit_time,
            signature_status,
        }
    }
}

/// The state of a password, with regards to git
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RepositoryStatus {
    /// The password is in git
    InRepo,
    /// The password isn't in git
    NotInRepo,
    /// The passwordstore isn't backed by a git repo
    #[default]
    NoRepo,
}

/// One password in the password store
#[derive(Clone, Debug, Default)]
pub struct PasswordEntry {
    pub id: Uuid,
    pub file_path: PathBuf,
    /// if we have a git repo, then commit time
    pub updated: Option<DateTime<Local>>,
    /// if we have a git repo, then the name of the committer
    pub committed_by: Option<String>,
    /// if we have a git repo, and the commit was signed
    pub signature_status: Option<SignatureStatus>,
    /// describes if the file is in a repository or not
    pub is_in_git: RepositoryStatus,
}

impl Serialize for PasswordEntry {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PasswordEntry", 6)?;
        state.serialize_field("id", &self.id.to_string())?;
        state.serialize_field("updated_at", &self.updated)?;
        state.serialize_field("committed_by", &self.committed_by)?;
        state.serialize_field("signature_status", &self.signature_status)?;
        state.serialize_field("is_in_git", &self.is_in_git)?;
        state.end()
    }
}

impl TryInto<serde_json::Value> for &PasswordEntry {
    type Error = serde_json::Error;

    fn try_into(self) -> std::result::Result<serde_json::Value, Self::Error> {
        serde_json::to_value(self)
    }
}
impl TryInto<serde_json::Map<String, serde_json::Value>> for &PasswordEntry {
    type Error = serde_json::Error;

    fn try_into(
        self,
    ) -> std::result::Result<serde_json::Map<String, serde_json::Value>, Self::Error> {
        serde_json::to_value(self)?
            .as_object()
            .cloned()
            .ok_or_else(|| {
                serde_json::Error::custom("expected a map, but got something else".to_owned())
            })
    }
}

impl PasswordEntry {
    /// constructs a a `PasswordEntry` from the supplied parts
    pub fn new(
        base: &Path,    // Root of the password directory
        relpath: &Path, // Relative path to the password.
        update_time: Result<DateTime<Local>>,
        committed_by: Result<String>,
        signature_status: Result<SignatureStatus>,
        is_in_git: RepositoryStatus,
    ) -> Self {
        Self {
            id: Uuid::from_str(&relpath.file_stem().unwrap().to_str().unwrap()).unwrap(),
            file_path: base.join(relpath),
            updated: update_time.ok(),
            committed_by: committed_by.ok(),
            signature_status: signature_status.ok(),
            is_in_git,
        }
    }
    pub fn get_username(&self) -> String {
        todo!()
    }
    pub fn get_domain(&self) -> String {
        todo!()
    }

    /// Consumes an `PasswordEntry`, and returns a new one with a new name
    pub fn with_new_name(old: Self, base: &Path, relpath: &Path) -> Self {
        Self {
            id: old.id,
            file_path: base.join(relpath),
            updated: old.updated,
            committed_by: old.committed_by,
            signature_status: old.signature_status,
            is_in_git: old.is_in_git,
        }
    }

    /// creates a `PasswordEntry` by running git blame on the specified path
    pub fn load_from_git(
        base: &Path,
        path: &Path,
        repo: &git2::Repository,
        store: &PasswordStore,
    ) -> Self {
        let (update_time, committed_by, signature_status) =
            repo.read_git_meta_data(base, path, store);

        let relpath = path
            .strip_prefix(base)
            .expect("base was not a prefix of path")
            .to_path_buf();
        Self::new(
            base,
            &relpath,
            update_time,
            committed_by,
            signature_status,
            RepositoryStatus::InRepo,
        )
    }

    /// creates a `PasswordEntry` based on data in the filesystem
    pub fn load_from_filesystem(base: &Path, relpath: &Path) -> Self {
        let filename =
            uuid::Uuid::from_str(&relpath.file_stem().unwrap().to_str().unwrap()).unwrap();
        Self {
            id: filename,
            file_path: base.join(relpath),
            updated: None,
            committed_by: None,
            signature_status: None,
            is_in_git: RepositoryStatus::NoRepo,
        }
    }

    /// Decrypts and returns the full content of the `PasswordEntry`
    /// # Errors
    /// Returns an `Err` if the path is empty
    pub fn secret(
        &self,
        store: &PasswordStore,
        passphrase_provider: Option<Handler>,
    ) -> Result<String> {
        let s = fs::metadata(&self.file_path)?;
        if s.len() == 0 {
            return Err(Error::Generic("empty password file"));
        }

        let content = fs::read(&self.file_path)?;
        if passphrase_provider.is_none() {
            store.crypto.decrypt_string(&content, passphrase_provider)
        } else {
            {
                let mut passphrase_provider2 = passphrase_provider.clone().unwrap();
                passphrase_provider2
                    .set_flag(crate::crypto::PassphraseProviderFlag::UseOnlyCached)?;
            }
            let res = store
                .crypto
                .decrypt_string(&content, passphrase_provider.clone());
            {
                let mut passphrase_provider2 = passphrase_provider.clone().unwrap();
                passphrase_provider2
                    .remove_flag(crate::crypto::PassphraseProviderFlag::UseOnlyCached)?;
                res
            }
        }
    }

    /// Decrypts and returns the first line of the `PasswordEntry`
    /// # Errors
    /// Returns an `Err` if the decryption fails
    pub fn password(&self, store: &PasswordStore) -> Result<String> {
        Ok(self.secret(store, None)?.split('\n').take(1).collect())
    }

    /// decrypts and returns a TOTP code if the entry contains a otpauth:// url
    /// # Errors
    /// Returns an `Err` if the code generation fails
    pub fn mfa(&self, store: &PasswordStore) -> Result<String> {
        let secret = self.secret(store, None)?;

        if let Some(start_pos) = secret.find("otpauth://") {
            let end_pos = {
                let mut end_pos = secret.len();
                for (pos, c) in secret.chars().skip(start_pos).enumerate() {
                    if c.is_whitespace() {
                        end_pos = pos + start_pos;
                        break;
                    }
                }
                end_pos
            };
            let totp = TOTP::from_url(&secret[start_pos..end_pos])?;
            Ok(totp.generate_current()?)
        } else {
            Err(Error::Generic("No otpauth:// url in secret"))
        }
    }

    fn update_internal(&self, secret: &str, store: &PasswordStore) -> Result<()> {
        if !store.valid_gpg_signing_keys.is_empty() {
            store.verify_gpg_id_files()?;
        }

        let recipients = store.recipients_for_path(&self.file_path)?;
        let ciphertext = store.crypto.encrypt_string(secret, &recipients)?;
        let mut output = File::create(&self.file_path)?;
        output.write_all(&ciphertext)?;
        Ok(())
    }

    pub fn update(
        &self,
        secret: String,
        store: &PasswordStore,
        passphrase_provider: Option<Handler>,
    ) -> Result<()> {
        self.update_internal(&secret, store)?;

        if store.repo().is_err() {
            return Ok(());
        }

        let message = format!("Edit content of entry with id: {}", &self.id);

        store.add(
            &[append_extension(
                PathBuf::from(&self.id.to_string()),
                ".gpg",
            )],
            &message,
            passphrase_provider,
            true,
        )?;

        Ok(())
    }

    pub fn delete_file(
        &self,
        store: &PasswordStore,
        passphrase_provider: Option<Handler>,
    ) -> Result<()> {
        std::fs::remove_file(&self.file_path)?;

        if store.repo().is_err() {
            warn!("repo is err,");
            return Ok(());
        }
        let message = format!("Removed password file for {} using rpass", &self.id);

        store.repo()?.remove_file(
            &[append_extension(
                PathBuf::from(&self.id.to_string()),
                ".gpg",
            )],
            store.get_crypto(),
            &message,
            passphrase_provider,
            // passphrase.as_deref(),
            true,
        )?;
        Ok(())
    }

    /// Returns a list of log lines for the password, one line for each commit that have changed
    /// that password in some way
    /// # Errors
    /// Returns an `Err` if any of the git operation fails.
    pub fn get_history(&self, store: &PasswordStore) -> Result<Vec<GitLogLine>> {
        let repo = {
            let repo_res = store.repo();
            if repo_res.is_err() {
                return Ok(vec![]);
            }
            repo_res?
        };

        let mut revwalk = repo.revwalk()?;

        revwalk.set_sorting(git2::Sort::REVERSE)?;
        revwalk.set_sorting(git2::Sort::TIME)?;

        revwalk.push_head()?;

        let p = self.file_path.strip_prefix(&store.root)?;
        let ps = git2::Pathspec::new(vec![&p])?;

        let mut diffopts = git2::DiffOptions::new();
        diffopts.pathspec(p);

        let walk_res: Vec<GitLogLine> = revwalk
            .filter_map(|id| {
                if let Ok(oid) = id {
                    if let Ok(commit) = repo.find_commit(oid) {
                        if commit.parents().len() == 0 {
                            if let Ok(tree) = commit.tree() {
                                let flags = git2::PathspecFlags::NO_MATCH_ERROR;
                                ps.match_tree(&tree, flags).ok()?;
                            } else {
                                return None;
                            }
                        } else {
                            let m = commit.parents().all(|parent| {
                                repo.match_with_parent(&commit, &parent, &mut diffopts)
                                    .unwrap_or(false)
                            });
                            if !m {
                                return None;
                            }
                        }

                        let time = commit.time();
                        let dt = to_result(Local.timestamp_opt(time.seconds(), 0)).ok()?;

                        let signature_status = repo.verify_git_signature(&oid, store);
                        Some(GitLogLine::new(
                            commit.message().unwrap_or("<no message>").to_owned(),
                            dt,
                            signature_status.ok(),
                        ))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        Ok(walk_res)
    }
}

/// Import the key_ids from the signature file from a keyserver.
/// # Errors
/// Returns an `Err` if the download fails
pub fn pgp_pull(store: &mut PasswordStore, config_path: &Path) -> Result<String> {
    let recipients = store.all_recipients()?;
    let recipients_refs: Vec<&Recipient> = recipients.iter().collect();

    let result = store.crypto.pull_keys(&recipients_refs, config_path)?;

    Ok(result)
}

/// Import a key from a string.
/// # Errors
/// Returns an `Err` if the import fails
pub fn pgp_import(store: &mut PasswordStore, text: &str, config_path: &Path) -> Result<String> {
    store.crypto.import_key(text, config_path)
}

/// Return a list of all passwords whose name contains `query`.
pub fn search(store: &PasswordStore, query: &str) -> Vec<PasswordEntry> {
    let passwords = &store.passwords;
    fn normalized(s: &str) -> String {
        s.to_lowercase()
    }
    fn matches(s: &str, q: &str) -> bool {
        normalized(s).as_str().contains(normalized(q).as_str())
    }
    let matching = passwords
        .iter()
        .filter(|p| matches(&p.id.to_string(), query));
    let res: Vec<PasswordEntry> = matching.cloned().collect();
    return res;
}

/// Determine password directory
pub fn password_dir(
    password_store_dir: &Option<PathBuf>,
    home: &Option<PathBuf>,
) -> Result<PathBuf> {
    let pass_home = password_dir_raw(password_store_dir, home);
    if !pass_home.exists() {
        return Err(Error::Generic("failed to locate password directory"));
    }
    Ok(pass_home)
}

/// Determine password directory
pub fn password_dir_raw(password_store_dir: &Option<PathBuf>, home: &Option<PathBuf>) -> PathBuf {
    // If a directory is provided via env var, use it
    match password_store_dir.as_ref() {
        Some(p) => p.clone(),
        None => match home {
            Some(h) => h.join(".password-store"),
            None => PathBuf::new().join(".password-store"),
        },
    }
}

fn home_exists(home: &Option<PathBuf>, settings: &config::Config) -> bool {
    if home.is_none() {
        return false;
    }
    let home = home.as_ref().unwrap();

    let home_dir = home.join(".password-store");
    if home_dir.exists() {
        if !home_dir.is_dir() {
            return false;
        }

        let stores_res = settings.get("stores");
        if let Ok(stores) = stores_res {
            let stores: HashMap<String, config::Value> = stores;

            for store_name in stores.keys() {
                let store: HashMap<String, config::Value> =
                    stores[store_name].clone().into_table().unwrap();

                let password_store_dir_opt = store.get("path");
                if let Some(p) = password_store_dir_opt {
                    let p_path = PathBuf::from(p.clone().into_str().unwrap());
                    let c1 = std::fs::canonicalize(home_dir.clone());
                    let c2 = std::fs::canonicalize(p_path);
                    if c1.is_ok() && c2.is_ok() && c1.unwrap() == c2.unwrap() {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    false
}

fn env_var_exists(store_dir: &Option<String>, signing_keys: &Option<String>) -> bool {
    store_dir.is_some() || signing_keys.is_some()
}

fn settings_file_exists(home: &Option<PathBuf>, xdg_config_home: &Option<PathBuf>) -> bool {
    if home.is_none() {
        return false;
    }
    let home = home.as_ref().unwrap();

    let xdg_config_file = match xdg_config_home.as_ref() {
        Some(p) => p.join("rpass/settings.toml"),
        None => home.join(".config/rpass/settings.toml"),
    };

    let xdg_config_file_dir = Path::new(&xdg_config_file);
    if xdg_config_file_dir.exists() {
        return fs::metadata(xdg_config_file_dir)
            .map_or(false, |config_file| config_file.len() != 0);
    }

    false
}

fn home_settings(home: &Option<PathBuf>) -> Result<config::Config> {
    let mut default_store = std::collections::HashMap::new();

    let home = home.as_ref().ok_or("no home directory set")?;

    default_store.insert(
        "path".to_owned(),
        home.join(".password-store/").to_string_lossy().to_string(),
    );

    let mut stores_map = std::collections::HashMap::new();
    stores_map.insert("default".to_owned(), default_store);

    let mut new_settings = config::Config::default();
    new_settings.set("stores", stores_map)?;

    Ok(new_settings)
}

fn var_settings(
    store_dir: &Option<String>,
    signing_keys: &Option<String>,
) -> Result<config::Config> {
    let mut default_store = std::collections::HashMap::new();

    if let Some(dir) = store_dir {
        if dir.ends_with('/') {
            default_store.insert("path".to_owned(), dir.clone());
        } else {
            default_store.insert("path".to_owned(), dir.clone() + "/");
        }
    }
    if let Some(keys) = signing_keys {
        default_store.insert("valid_signing_keys".to_owned(), keys.clone());
    } else {
        default_store.insert("valid_signing_keys".to_owned(), "-1".to_owned());
    }

    let mut stores_map = std::collections::HashMap::new();
    stores_map.insert("default".to_owned(), default_store);

    let mut new_settings = config::Config::default();
    new_settings.set("stores", stores_map)?;

    Ok(new_settings)
}

fn xdg_config_file_location(
    home: &Option<PathBuf>,
    xdg_config_home: &Option<PathBuf>,
) -> Result<PathBuf> {
    match xdg_config_home.as_ref() {
        Some(p) => Ok(p.join("rpass/settings.toml")),
        None => {
            if let Some(h) = home {
                Ok(h.join(".config/rpass/settings.toml"))
            } else {
                Err(Error::Generic("no home directory"))
            }
        }
    }
}

fn file_settings(xdg_config_file: &Path) -> config::File<config::FileSourceFile> {
    config::File::from(xdg_config_file.to_path_buf())
}

fn append_extension(path: PathBuf, extension: &str) -> PathBuf {
    let mut str = path.into_os_string();
    str.push(extension);
    PathBuf::from(str)
}

/// reads rpasss config file, in `$XDG_CONFIG_HOME/rpass/settings.toml`
pub fn read_config(
    store_dir: &Option<String>,
    signing_keys: &Option<String>,
    home: &Option<PathBuf>,
    xdg_config_home: &Option<PathBuf>,
) -> Result<(config::Config, PathBuf)> {
    let mut settings = config::Config::default();
    let config_file_location = xdg_config_file_location(home, xdg_config_home)?;

    if settings_file_exists(home, xdg_config_home) {
        settings.merge(file_settings(&config_file_location))?;
    }

    if home_exists(home, &settings) {
        settings.merge(home_settings(home)?)?;
    }

    if env_var_exists(store_dir, signing_keys) {
        settings.merge(var_settings(store_dir, signing_keys)?)?;
    }

    Ok((settings, config_file_location))
}

pub fn save_config(
    stores: Arc<Mutex<Vec<Arc<Mutex<PasswordStore>>>>>,
    config_file_location: &Path,
) -> Result<()> {
    let mut stores_map = std::collections::HashMap::new();
    let stores_borrowed = stores
        .lock()
        .map_err(|_e| Error::Generic("problem locking the mutex"))?;
    #[allow(clippy::significant_drop_in_scrutinee)]
    for store in stores_borrowed.iter() {
        let store = store
            .lock()
            .map_err(|_e| Error::Generic("problem locking the mutex"))?;
        let mut store_map = std::collections::HashMap::new();
        store_map.insert(
            "path",
            store
                .get_store_path()
                .to_string_lossy()
                .into_owned()
                .to_string(),
        );
        if !store.get_valid_gpg_signing_keys().is_empty() {
            store_map.insert(
                "valid_signing_keys",
                store
                    .get_valid_gpg_signing_keys()
                    .iter()
                    .map(hex::encode_upper)
                    .collect::<Vec<String>>()
                    .join(","),
            );
        }

        store_map.insert(
            "pgp_implementation",
            store.crypto.implementation().to_string(),
        );
        stores_map.insert(store.get_name().clone(), store_map);
    }

    let mut settings = std::collections::HashMap::new();
    settings.insert("stores", stores_map);

    let f = std::fs::File::create(config_file_location)?;
    let mut f = std::io::BufWriter::new(f);
    f.write_all(toml::ser::to_string_pretty(&settings)?.as_bytes())?;

    Ok(())
}

#[cfg(test)]
#[path = "tests/pass.rs"]
mod pass_tests;
