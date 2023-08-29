use std::{
    collections::HashMap,
    fmt::{Display, Formatter, Write},
    fs,
    fs::File,
    io::Write as IoWrite,
    panic::{RefUnwindSafe, UnwindSafe},
    path::Path,
    sync::Arc,
};

pub use crate::error::{Error, Result};
use crate::{
    crypto::VerificationError::InfrastructureError,
    pass::OwnerTrustLevel,
    signature::{KeyRingStatus, Recipient, SignatureStatus},
};
use gpgme::PassphraseRequest;
use hex::FromHex;

/// The different pgp implementations we support
#[non_exhaustive]
#[derive(PartialEq, Eq, Debug)]
pub enum CryptoImpl {
    /// Implemented with the help of the gpgme crate
    GpgMe,
}

impl std::convert::TryFrom<&str> for CryptoImpl {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "gpg" => Ok(Self::GpgMe),
            _ => Err(Error::Generic(
                "unknown pgp implementation value, valid values are 'gpg'",
            )),
        }
    }
}

impl Display for CryptoImpl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            Self::GpgMe => write!(f, "gpg"),
        }?;
        Ok(())
    }
}

/// The different types of errors that can occur when doing a signature verification
#[non_exhaustive]
#[derive(Debug)]
pub enum VerificationError {
    /// Error message from the pgp library.
    InfrastructureError(String),
    /// The data was signed, but not from one of the supplied recipients.
    SignatureFromWrongRecipient,
    /// The signature was invalid,
    BadSignature,
    /// No signature found.
    MissingSignatures,
    /// More than one signature, this shouldn't happen and can indicate that someone have tried
    /// to trick the process by appending an additional signature.
    TooManySignatures,
}

impl From<std::io::Error> for VerificationError {
    fn from(err: std::io::Error) -> Self {
        InfrastructureError(format!("{err:?}"))
    }
}

impl From<crate::error::Error> for VerificationError {
    fn from(err: crate::error::Error) -> Self {
        InfrastructureError(format!("{err:?}"))
    }
}

impl From<anyhow::Error> for VerificationError {
    fn from(err: anyhow::Error) -> Self {
        InfrastructureError(format!("{err:?}"))
    }
}

/// The strategy for finding the gpg key to sign with can either be to look at the git
/// config, or ask gpg.
#[non_exhaustive]
pub enum FindSigningFingerprintStrategy {
    /// Will look at the git configuration to find the users fingerprint
    GIT,
    /// Will ask gpg to find the users fingerprint
    GPG,
}

/// Models the interactions that can be done on a pgp key
pub trait Key {
    /// returns a list of names associated with the key
    fn user_id_names(&self) -> Vec<String>;

    /// returns the keys fingerprint
    fn fingerprint(&self) -> Result<[u8; 20]>;

    /// returns if the key isn't usable
    fn is_not_usable(&self) -> bool;
}

/// A key gotten from gpgme
pub struct GpgMeKey {
    /// The key, gotten from gpgme.
    key: gpgme::Key,
}

impl Key for GpgMeKey {
    fn user_id_names(&self) -> Vec<String> {
        self.key
            .user_ids()
            .map(|user_id| user_id.name().unwrap_or("?").to_owned())
            .collect()
    }

    fn fingerprint(&self) -> Result<[u8; 20]> {
        let fp = self.key.fingerprint()?;

        Ok(<[u8; 20]>::from_hex(fp)?)
    }

    fn is_not_usable(&self) -> bool {
        self.key.is_bad()
            || self.key.is_revoked()
            || self.key.is_expired()
            || self.key.is_disabled()
            || self.key.is_invalid()
    }
}

/// All operations that can be done through pgp, either with gpgme.
pub trait Crypto {
    /// Reads a file and decrypts it
    /// # Errors
    /// Will return `Err` if decryption fails, for example if the current user isn't the
    /// recipient of the message.
    fn decrypt_string(&self, ciphertext: &[u8], passphrase: Option<String>) -> Result<String>;
    /// Encrypts a string
    /// # Errors
    /// Will return `Err` if encryption fails, for example if the current users key
    /// isn't capable of encrypting.
    fn encrypt_string(&self, plaintext: &str, recipients: &[Recipient]) -> Result<Vec<u8>>;

    /// Returns a gpg signature for the supplied string. Suitable to add to a gpg commit.
    /// # Errors
    /// Will return `Err` if signing fails, for example if the current users key
    /// isn't capable of signing.
    fn sign_string(
        &self,
        to_sign: &str,
        valid_gpg_signing_keys: &[[u8; 20]],
        strategy: &FindSigningFingerprintStrategy,
    ) -> Result<String>;
    fn sign_string_passphrase(
        &self,
        to_sign: &str,
        valid_gpg_signing_keys: &[[u8; 20]],
        strategy: &FindSigningFingerprintStrategy,
        passphrase: &str,
    ) -> Result<String>;

    /// Verifies is a signature is valid
    /// # Errors
    /// Will return `Err` if the verifican fails.
    fn verify_sign(
        &self,
        data: &[u8],
        sig: &[u8],
        valid_signing_keys: &[[u8; 20]],
    ) -> std::result::Result<SignatureStatus, VerificationError>;

    /// Returns true if a recipient is in the users keyring.
    fn is_key_in_keyring(&self, recipient: &Recipient) -> Result<bool>;

    /// Pull keys from the keyserver for those recipients.
    /// # Errors
    /// Will return `Err` on network errors and similar.
    fn pull_keys(&mut self, recipients: &[&Recipient], config_path: &Path) -> Result<String>;

    /// Import a key from text.
    /// # Errors
    /// Will return `Err` if the text wasn't able to be imported as a key.
    fn import_key(&mut self, key: &str, config_path: &Path) -> Result<String>;

    /// Return a key corresponding to the given key id.
    /// # Errors
    /// Will return `Err` if `key_id` didn't correspond to a key.
    fn get_key(&self, key_id: &str) -> Result<Box<dyn crate::crypto::Key>>;

    /// Returns a map from key fingerprints to OwnerTrustLevel's
    /// # Errors
    /// Will return `Err` on failure to obtain trust levels.
    fn get_all_trust_items(&self) -> Result<HashMap<[u8; 20], crate::signature::OwnerTrustLevel>>;

    /// Returns the type of this `CryptoImpl`, useful for serializing the store config
    fn implementation(&self) -> CryptoImpl;

    /// Returns the fingerprint of the user using rpass
    fn own_fingerprint(&self) -> Option<[u8; 20]>;
}

/// Used when the user configures gpgme to be used as a pgp backend.
#[non_exhaustive]
pub struct GpgMe {
    // passphrase_provider: Option<Box<PassphraseProvider>>,
}
impl Clone for PassphraseProvider {
    fn clone(&self) -> Self {
        PassphraseProvider {
            passphrase: self.passphrase.clone(),
        }
    }
}
pub struct PassphraseProvider {
    passphrase: Option<String>,
}
unsafe impl Sync for PassphraseProvider {}
unsafe impl Send for PassphraseProvider {}
impl RefUnwindSafe for PassphraseProvider {}
impl gpgme::PassphraseProvider for PassphraseProvider {
    fn get_passphrase(
        &mut self,
        request: PassphraseRequest,
        out: &mut dyn std::io::Write,
    ) -> gpgme::error::Result<()> {
        if let Some(passphrase) = &self.passphrase {
            out.write_all(passphrase.as_bytes())?;
        } else {
            out.write_all(b"abcd")?;
        }
        Ok(())
    }
}
impl Crypto for GpgMe {
    fn decrypt_string(&self, ciphertext: &[u8], passphrase: Option<String>) -> Result<String> {
        let passphrase_provider = PassphraseProvider { passphrase };
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        let mut output = Vec::new();
        ctx.set_pinentry_mode(gpgme::PinentryMode::Loopback)?;
        let mut ctx_with_passphrase_provider = ctx.set_passphrase_provider(passphrase_provider);
        ctx_with_passphrase_provider.decrypt(ciphertext, &mut output)?;
        return Ok(String::from_utf8(output)?);
    }

    fn encrypt_string(&self, plaintext: &str, recipients: &[Recipient]) -> Result<Vec<u8>> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        ctx.set_armor(false);

        let mut keys = Vec::new();
        for recipient in recipients {
            if recipient.key_ring_status == KeyRingStatus::NotInKeyRing {
                return Err(Error::RecipientNotInKeyRing(recipient.key_id.clone()));
            }
            keys.push(ctx.get_key(recipient.key_id.clone())?);
        }

        let mut output = Vec::new();
        ctx.encrypt_with_flags(
            &keys,
            plaintext,
            &mut output,
            gpgme::EncryptFlags::NO_COMPRESS,
        )?;

        Ok(output)
    }
    fn sign_string_passphrase(
        &self,
        to_sign: &str,
        valid_gpg_signing_keys: &[[u8; 20]],
        strategy: &FindSigningFingerprintStrategy,
        passphrase: &str,
    ) -> Result<String> {
        let passphrase_provider = PassphraseProvider {
            passphrase: Some(passphrase.to_owned()),
        };
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        ctx.set_pinentry_mode(gpgme::PinentryMode::Loopback)?;
        let mut ctx = ctx.set_passphrase_provider(passphrase_provider);
        let mut config = git2::Config::open_default()?;
        // eprintln!(
        //     "config: {:?}",
        //     config.set_str(
        //         "user.signingkey",
        //         "F40FBF4B025339DEA21D3D2D3E1DDD1257F3A8F1"
        //     )
        // );

        let signing_key = match strategy {
            FindSigningFingerprintStrategy::GIT => config.get_string("user.signingkey")?,
            FindSigningFingerprintStrategy::GPG => {
                let mut key_opt: Option<gpgme::Key> = None;

                for key_id in valid_gpg_signing_keys {
                    let key_res = ctx.get_key(hex::encode_upper(key_id));

                    if let Ok(r) = key_res {
                        key_opt = Some(r);
                    }
                }

                if let Some(key) = key_opt {
                    key.fingerprint()?.to_owned()
                } else {
                    return Err(Error::Generic("no valid signing key"));
                }
            }
        };

        ctx.set_armor(true);
        let key = ctx.get_secret_key(signing_key)?;

        ctx.add_signer(&key)?;
        let mut output = Vec::new();
        let signature = ctx.sign_detached(to_sign, &mut output);

        if let Err(e) = signature {
            return Err(Error::Gpg(e));
        }

        Ok(String::from_utf8(output)?)
    }

    fn sign_string(
        &self,
        to_sign: &str,
        valid_gpg_signing_keys: &[[u8; 20]],
        strategy: &FindSigningFingerprintStrategy,
    ) -> Result<String> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        let config = git2::Config::open_default()?;

        let signing_key = match strategy {
            FindSigningFingerprintStrategy::GIT => config.get_string("user.signingkey")?,
            FindSigningFingerprintStrategy::GPG => {
                let mut key_opt: Option<gpgme::Key> = None;

                for key_id in valid_gpg_signing_keys {
                    let key_res = ctx.get_key(hex::encode_upper(key_id));

                    if let Ok(r) = key_res {
                        key_opt = Some(r);
                    }
                }

                if let Some(key) = key_opt {
                    key.fingerprint()?.to_owned()
                } else {
                    return Err(Error::Generic("no valid signing key"));
                }
            }
        };

        ctx.set_armor(true);
        let key = ctx.get_secret_key(signing_key)?;

        ctx.add_signer(&key)?;
        let mut output = Vec::new();
        let signature = ctx.sign_detached(to_sign, &mut output);

        if let Err(e) = signature {
            return Err(Error::Gpg(e));
        }

        Ok(String::from_utf8(output)?)
    }

    fn verify_sign(
        &self,
        data: &[u8],
        sig: &[u8],
        valid_signing_keys: &[[u8; 20]],
    ) -> std::result::Result<SignatureStatus, VerificationError> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)
            .map_err(|e| VerificationError::InfrastructureError(format!("{e:?}")))?;

        let result = ctx
            .verify_detached(sig, data)
            .map_err(|e| VerificationError::InfrastructureError(format!("{e:?}")))?;

        let mut sig_sum = None;

        for (i, s) in result.signatures().enumerate() {
            let fpr = s
                .fingerprint()
                .map_err(|e| VerificationError::InfrastructureError(format!("{e:?}")))?;

            let fpr = <[u8; 20]>::from_hex(fpr)
                .map_err(|e| VerificationError::InfrastructureError(format!("{e:?}")))?;

            if !valid_signing_keys.contains(&fpr) {
                return Err(VerificationError::SignatureFromWrongRecipient);
            }
            if i == 0 {
                sig_sum = Some(s.summary());
            } else {
                return Err(VerificationError::TooManySignatures);
            }
        }

        match sig_sum {
            None => Err(VerificationError::MissingSignatures),
            Some(sig_sum) => {
                let sig_status: SignatureStatus = sig_sum.into();
                match sig_status {
                    SignatureStatus::Bad => Err(VerificationError::BadSignature),
                    SignatureStatus::Good | SignatureStatus::AlmostGood => Ok(sig_status),
                }
            }
        }
    }

    fn is_key_in_keyring(&self, recipient: &Recipient) -> Result<bool> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        if let Some(fingerprint) = recipient.fingerprint {
            Ok(ctx.get_key(hex::encode(fingerprint)).is_ok())
        } else {
            Ok(false)
        }
    }

    fn pull_keys(&mut self, recipients: &[&Recipient], _config_path: &Path) -> Result<String> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        let mut result_str = String::new();
        for recipient in recipients {
            let response = download_keys(&recipient.key_id)?;

            let result = ctx.import(response)?;

            write!(
                result_str,
                "{}: import result: {:?}\n\n",
                recipient.key_id, result
            )?;
        }

        Ok(result_str)
    }

    fn import_key(&mut self, key: &str, _config_path: &Path) -> Result<String> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        let result = ctx.import(key)?;

        let result_str = format!("Import result: {result:?}\n\n");

        Ok(result_str)
    }

    fn get_key(&self, key_id: &str) -> Result<Box<dyn crate::crypto::Key>> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        Ok(Box::new(GpgMeKey {
            key: ctx.get_key(key_id)?,
        }))
    }

    fn get_all_trust_items(&self) -> Result<HashMap<[u8; 20], crate::signature::OwnerTrustLevel>> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        ctx.set_key_list_mode(gpgme::KeyListMode::SIGS)?;

        let keys = ctx.find_keys(vec![String::new()])?;

        let mut trusts = HashMap::new();
        for key_res in keys {
            let key = key_res?;
            trusts.insert(
                <[u8; 20]>::from_hex(key.fingerprint()?)?,
                crate::signature::OwnerTrustLevel::from(&key.owner_trust()),
            );
        }

        Ok(trusts)
    }

    fn implementation(&self) -> CryptoImpl {
        CryptoImpl::GpgMe
    }

    fn own_fingerprint(&self) -> Option<[u8; 20]> {
        None
    }
}

/// Tries to download keys from keys.openpgp.org
fn download_keys(recipient_key_id: &str) -> Result<String> {
    let url = match recipient_key_id.len() {
        16 => format!("https://keys.openpgp.org/vks/v1/by-keyid/{recipient_key_id}"),
        18 if recipient_key_id.starts_with("0x") => format!(
            "https://keys.openpgp.org/vks/v1/by-keyid/{}",
            &recipient_key_id[2..]
        ),
        40 => format!("https://keys.openpgp.org/vks/v1/by-fingerprint/{recipient_key_id}"),
        42 if recipient_key_id.starts_with("0x") => format!(
            "https://keys.openpgp.org/vks/v1/by-fingerprint/{}",
            &recipient_key_id[2..]
        ),
        _ => return Err(Error::Generic("key id is not 16 or 40 hex chars")),
    };

    Ok(reqwest::blocking::get(url)?.text()?)
}

/// Intended for usage with slices containing a v4 fingerprint.
pub fn slice_to_20_bytes(b: &[u8]) -> Result<[u8; 20]> {
    if b.len() != 20 {
        return Err(Error::Generic("slice isn't 20 bytes"));
    }

    let mut f: [u8; 20] = [0; 20];
    f.copy_from_slice(&b[0..20]);

    Ok(f)
}

#[cfg(test)]
#[path = "tests/crypto.rs"]
mod crypto_tests;
