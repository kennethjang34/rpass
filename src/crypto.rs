use log::*;
use pinentry::PassphraseInput;
use secrecy::ExposeSecret;
use std::{
    collections::HashMap,
    ffi::CStr,
    fmt::{Debug, Display, Formatter, Write},
    io,
    ops::AddAssign,
    path::Path,
    sync::{Arc, Mutex, RwLock},
};

pub use crate::error::{Error, Result};
use crate::{
    crypto::VerificationError::InfrastructureError,
    signature::{KeyRingStatus, Recipient, SignatureStatus},
};
use gpgme::{Context, ContextWithCallbacks, PassphraseRequest};
use gpgme::{KeyListMode, StatusHandler};
use hex::FromHex;

/// The different pgp implementations we support
#[non_exhaustive]
#[derive(PartialEq, Eq, Debug)]
pub enum CryptoImpl {
    /// Implemented with the help of the gpgme crate
    GpgMe,
}

impl CryptoImpl {
    /// Returns a new instance of the crypto implementation
    pub fn get_crypto_type(&self) -> Result<Box<dyn Crypto + Send>> {
        match self {
            Self::GpgMe => Ok(Box::new(GpgMe {})),
        }
    }
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
impl Debug for dyn Key {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key {{")?;
        write!(f, "user_id_names: {:?}", self.user_id_names())?;
        write!(f, ", fingerprint: {:?}", self.fingerprint())?;
        write!(f, ", is_not_usable: {:?}", self.is_not_usable())?;
        write!(f, ", has_secret: {:?}", self.has_secret())?;
        write!(f, "}}")?;
        Ok(())
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

    fn get_user_name(&self) -> Option<String>;

    /// returns the keys fingerprint
    fn fingerprint(&self) -> Result<[u8; 20]>;
    fn primary_user_id(&self) -> Option<String>;

    /// returns if the key isn't usable
    fn is_not_usable(&self) -> bool;
    /// returns if the key isn't usable
    fn has_secret(&self) -> bool;
    /// returns if the key can sign
    fn can_sign(&self) -> bool;
    /// returns if the key can encrypt
    fn can_encrypt(&self) -> bool;
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
    fn get_user_name(&self) -> Option<String> {
        self.key
            .user_ids()
            .next()
            .map(|user_id| user_id.name().unwrap_or("?").to_owned())
    }

    fn fingerprint(&self) -> Result<[u8; 20]> {
        let fp = self.key.fingerprint()?;

        Ok(<[u8; 20]>::from_hex(fp)?)
    }
    fn primary_user_id(&self) -> Option<String> {
        let user_id = self.key.user_ids().next();
        user_id.map(|user_id| user_id.email().unwrap_or("?").to_owned())
    }

    fn is_not_usable(&self) -> bool {
        self.key.is_bad()
            || self.key.is_revoked()
            || self.key.is_expired()
            || self.key.is_disabled()
            || self.key.is_invalid()
    }
    fn has_secret(&self) -> bool {
        self.key.has_secret()
    }
    fn can_sign(&self) -> bool {
        self.key.can_sign()
    }
    fn can_encrypt(&self) -> bool {
        self.key.can_encrypt()
    }
}
pub fn get_keys(crypto_impl: CryptoImpl) -> Result<Vec<Box<dyn Key>>> {
    match crypto_impl {
        CryptoImpl::GpgMe => {
            let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
            ctx.set_key_list_mode(KeyListMode::WITH_SECRET)?;
            let keys = ctx.keys()?;
            let mut res = Vec::new();
            for key in keys {
                let key = key?;
                res.push(Box::new(GpgMeKey { key }) as Box<dyn Key>);
            }
            Ok(res)
        }
    }
}

/// All operations that can be done through pgp, either with gpgme.
pub trait Crypto: Debug {
    // fn get_passphrase_provider(&self) -> Option<Arc<Mutex<PassphraseProvider>>>;
    /// Reads a file and decrypts it
    /// # Errors
    /// Will return `Err` if decryption fails, for example if the current user isn't the
    /// recipient of the message.
    fn try_passphrases(
        &self,
        recipients: &[Recipient],
        passphrase_provider: Option<Handler>,
        max_tries: Option<u8>,
    ) -> Result<Option<Recipient>>;
    fn decrypt_string(
        &self,
        ciphertext: &[u8],
        passphrase_provider: Option<Handler>,
    ) -> Result<String>;
    /// Encrypts a string
    /// # Errors
    /// Will return `Err` if encryption fails, for example if the current users key
    /// isn't capable of encrypting.
    fn encrypt_string(&self, plaintext: &str, recipients: &[Recipient]) -> Result<Vec<u8>>;

    // fn verify_passphrase(&self, user_id: Option<String>, passphrase: &str) -> Result<bool>;

    /// Returns a gpg signature for the supplied string. Suitable to add to a gpg commit.
    /// # Errors
    /// Will return `Err` if signing fails, for example if the current users key
    /// isn't capable of signing.
    fn sign_string(
        &self,
        to_sign: &str,
        valid_gpg_signing_keys: &[[u8; 20]],
        strategy: &FindSigningFingerprintStrategy,
        passphrase_provider: Option<Handler>,
        config: Option<git2::Config>,
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
    // fn verify_sign_uid(
    //     &self,
    //     data: &[u8],
    //     sig: &[u8],
    //     valid_signing_keys: &[String],
    // ) -> std::result::Result<SignatureStatus, VerificationError>;

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
pub struct GpgMe {}
impl Clone for Handler {
    fn clone(&self) -> Self {
        Handler {
            passphrases: self.passphrases.clone(),
            last_tried_key_user_id_hint: self.last_tried_key_user_id_hint.clone(),
            request: self.request.clone(),
            last_tried_recipient: self.last_tried_recipient.clone(),
            recipient_to_user_id_hint: self.recipient_to_user_id_hint.clone(),
            failure_count: self.failure_count.clone(),
            err_msg: self.err_msg.clone(),
        }
    }
}
impl Default for Handler {
    fn default() -> Self {
        Handler {
            passphrases: Arc::new(RwLock::new(HashMap::new())),
            last_tried_key_user_id_hint: Arc::new(Mutex::new(None)),
            recipient_to_user_id_hint: Arc::new(Mutex::new(HashMap::new())),
            request: None,
            last_tried_recipient: Arc::new(Mutex::new(None)),
            failure_count: Arc::new(Mutex::new(0)),
            err_msg: Arc::new(Mutex::new(None)),
        }
    }
}

pub fn get_signing_key(
    ctx: &mut Context,
    strategy: &FindSigningFingerprintStrategy,
    valid_gpg_signing_keys: &[[u8; 20]],
    config: git2::Config,
) -> Result<Option<String>> {
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
    return Ok(Some(signing_key));
}
// unsafe impl Sync for PassphraseProvider {}
// unsafe impl Send for PassphraseProvider {}
#[derive(Debug)]
pub struct Handler {
    pub passphrases: Arc<RwLock<HashMap<String, String>>>,
    pub last_tried_key_user_id_hint: Arc<Mutex<Option<String>>>,
    pub recipient_to_user_id_hint: Arc<Mutex<HashMap<String, String>>>,
    pub request: Option<String>,
    pub last_tried_recipient: Arc<Mutex<Option<Recipient>>>,
    pub failure_count: Arc<Mutex<u8>>,
    pub err_msg: Arc<Mutex<Option<String>>>,
}

impl Handler {
    pub fn new(passphrases: Arc<RwLock<HashMap<String, String>>>) -> Self {
        Handler {
            passphrases,
            last_tried_key_user_id_hint: Arc::new(Mutex::new(None)),
            recipient_to_user_id_hint: Arc::new(Mutex::new(HashMap::new())),
            request: None,
            last_tried_recipient: Arc::new(Mutex::new(None)),
            failure_count: Arc::new(Mutex::new(0)),
            err_msg: Arc::new(Mutex::new(None)),
        }
    }
    pub fn create_context<'a, 'b>(&'a mut self) -> gpgme::Result<gpgme::ContextWithCallbacks<'b>> {
        let ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        let mut ctx = ctx.set_passphrase_provider(self.clone());
        ctx.set_key_list_mode(KeyListMode::WITH_SECRET)?;
        ctx.set_key_list_mode(KeyListMode::WITH_KEYGRIP)?;
        ctx.set_pinentry_mode(gpgme::PinentryMode::Loopback)?;
        ctx.set_status_handler(self.clone());
        ctx.set_progress_reporter(|_progress_info: gpgme::ProgressInfo<'_>| {});
        Ok(ctx)
    }
    pub fn clear_passphrases(&mut self) -> Result<()> {
        let mut write_lock = self
            .passphrases
            .write()
            .map_err(|e| Error::GenericDyn(format!("failed to lock passphrases. {:?}", e)))?;
        write_lock.clear();
        return Ok(());
    }
    pub fn remove_passphrase(&mut self, key_id: &str, include_subkeys: bool) -> Result<()> {
        let mut write_lock = self
            .passphrases
            .write()
            .map_err(|e| Error::GenericDyn(format!("failed to lock passphrases. {:?}", e)))?;
        if include_subkeys {
            let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
            if let Ok(key) = ctx.get_secret_key(key_id) {
                for subkey in key.subkeys() {
                    let key_id = subkey.id().unwrap();
                    write_lock.remove(key_id);
                }
            }
        } else {
            write_lock.remove(key_id);
        }
        return Ok(());
    }
}

impl From<&mut Handler> for ContextWithCallbacks<'_> {
    fn from(handler: &mut Handler) -> Self {
        handler.create_context().unwrap()
    }
}
impl Handler {
    fn prompt_pinentry(
        &mut self,
        key_id: Option<&str>,
        error_msg: Option<String>,
    ) -> std::result::Result<String, pinentry::Error> {
        let passphrase = if let Some(mut prompt) = PassphraseInput::with_binary("pinentry-mac") {
            let description = format!(
                "Enter passphrase of {} for {:?}",
                key_id.unwrap_or("key id not passed"),
                &self.request.as_ref().unwrap_or(&"no request".to_owned())
            );
            let prompt = prompt
                .with_description(&description)
                .with_prompt("Passphrase:");
            if let Some(error_msg) = error_msg {
                prompt.with_error(error_msg.as_ref()).interact()
            } else {
                prompt.interact()
            }
        } else {
            if let Some(mut input) = PassphraseInput::with_default_binary() {
                // pinentry binary is available!
                input
                    .with_description(&format!(
                        "Enter passphrase for {}",
                        key_id.unwrap_or("key id not passed")
                    ))
                    .with_prompt("Passphrase:")
                    .interact()
            } else {
                Err(pinentry::Error::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no default pinentry",
                )))
            }
        };
        if passphrase.is_err() {
            self.failure_count.lock().unwrap().add_assign(1);
        }
        passphrase.map(|s| s.expose_secret().to_owned())
    }
}
impl StatusHandler for Handler {
    fn handle<'a, 'b>(
        &'a mut self,
        _keyword: Option<&'b CStr>,
        args: Option<&'b CStr>,
    ) -> gpgme::Result<()> {
        if args.is_some_and(move |s| {
            let s = s.to_str().unwrap_or_default();
            s == "ERROR" || s == "FAILURE"
        }) {
            let last_tried_recipient = self.last_tried_recipient.lock().unwrap().to_owned();
            if let Some(ref last_tried_recipient) = last_tried_recipient {
                if let Some(store_id) = self
                    .recipient_to_user_id_hint
                    .lock()
                    .unwrap()
                    .get(last_tried_recipient.key_id.as_str())
                    .map(|s| s.to_owned())
                {
                    return self
                        .passphrases
                        .write()
                        .unwrap()
                        .remove(&store_id)
                        .map(|_| ())
                        .ok_or(gpgme::Error::NOT_FOUND);
                } else {
                    return self
                        .passphrases
                        .write()
                        .unwrap()
                        .remove(last_tried_recipient.key_id.as_str())
                        .map(|_| ())
                        .ok_or(gpgme::Error::NOT_FOUND);
                }
            } else {
                return Err(gpgme::Error::NOT_FOUND);
            }
        } else {
            Ok(())
        }
    }
}
impl gpgme::PassphraseProvider for Handler {
    fn get_passphrase(
        &mut self,
        request: PassphraseRequest,
        out: &mut dyn std::io::Write,
    ) -> gpgme::error::Result<()> {
        let mut user_id_hint = request.user_id_hint().map(|s| s.to_string()).ok();
        if let Some(user_id_hint) = user_id_hint.as_mut() {
            let mut user_id_hint_iter = user_id_hint.split(" ");
            let next_hint = user_id_hint_iter.next();
            if let Some(next_hint) = next_hint {
                *user_id_hint = next_hint.to_string();
                if let Some(ref recipient) = self.last_tried_recipient.lock().unwrap().as_ref() {
                    self.recipient_to_user_id_hint
                        .lock()
                        .unwrap()
                        .insert(recipient.key_id.clone(), user_id_hint.clone());
                }
            }
        }
        if let Some(ref user_id_hint) = user_id_hint {
            let mut locked = self.last_tried_key_user_id_hint.lock().unwrap();
            locked.replace(user_id_hint.clone());
        }
        let passphrase = {
            if request.prev_attempt_failed && user_id_hint.is_some() {
                self.passphrases
                    .write()
                    .unwrap()
                    .remove(user_id_hint.as_ref().unwrap());
            }
            let passphrases = self.passphrases.clone();
            let read_lock = passphrases.read();
            if let Some(user_id_hint) = user_id_hint {
                let res = if let Ok(locked) = read_lock {
                    let passphrase = if let Some(passphrase) = locked.get(&user_id_hint) {
                        Ok(passphrase.to_owned())
                    } else {
                        let err_msg = self.err_msg.clone().lock().unwrap().to_owned();
                        let res = self.prompt_pinentry(Some(&user_id_hint), err_msg);
                        res.map_err(|e| {
                            error!("failed to prompt pinentry: {:?}", e);
                            gpgme::error::Error::PIN_ENTRY
                        })
                    };
                    drop(locked);
                    passphrase
                } else {
                    error!("failed to lock lock passphrase cache. {:?}", read_lock);
                    drop(read_lock);
                    let err_msg = self.err_msg.clone().lock().unwrap().to_owned();
                    let res = self.prompt_pinentry(Some(&user_id_hint), err_msg);
                    res.map_err(|e| {
                        error!("failed to prompt pinentry: {:?}", e);
                        gpgme::error::Error::PIN_ENTRY
                    })
                };
                if res.is_ok() {
                    self.passphrases
                        .write()
                        .unwrap()
                        .insert(user_id_hint, res.as_ref().unwrap().to_owned());
                }
                res
            } else {
                let res = self.prompt_pinentry(None, None);
                res.map_err(|e| {
                    error!("failed to prompt pinentry: {:?}", e);
                    gpgme::error::Error::PIN_ENTRY
                })
            }
        };
        if let Ok(passphrase) = passphrase {
            out.write_all((passphrase).as_bytes())?;
            Ok(())
        } else {
            passphrase.map(|_| ())
        }
    }
}

impl Debug for GpgMe {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "GpgMe")
    }
}

impl Crypto for GpgMe {
    fn decrypt_string(
        &self,
        ciphertext: &[u8],
        passphrase_provider: Option<Handler>,
    ) -> Result<String> {
        let mut passphrase_provider = passphrase_provider.unwrap_or_default();
        let mut output = Vec::new();
        let mut ctx = passphrase_provider.create_context()?;
        ctx.decrypt(ciphertext, &mut output)?;
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
    fn sign_string(
        &self,
        to_sign: &str,
        valid_gpg_signing_keys: &[[u8; 20]],
        strategy: &FindSigningFingerprintStrategy,
        passphrase_provider: Option<Handler>,
        config: Option<git2::Config>,
    ) -> Result<String> {
        let config = config.unwrap_or_else(|| git2::Config::open_default().unwrap());

        if let Some(mut passphrase_provider) = passphrase_provider {
            let mut ctx = passphrase_provider.create_context()?;
            let signing_key = get_signing_key(&mut ctx, strategy, valid_gpg_signing_keys, config)?
                .ok_or(Error::Generic("no valid signing key"))?;
            ctx.set_armor(true);
            let key = ctx.get_secret_key(signing_key)?;
            ctx.add_signer(&key)?;
            let mut output = Vec::new();
            let signature = ctx.sign_detached(to_sign, &mut output);
            if let Err(e) = signature {
                return Err(Error::Gpg(e));
            }

            Ok(String::from_utf8(output)?)
        } else {
            let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
            ctx.set_armor(true);
            let signing_key = get_signing_key(&mut ctx, strategy, valid_gpg_signing_keys, config)?
                .ok_or(Error::Generic("no valid signing key"))?;
            let key = ctx.get_secret_key(signing_key)?;

            ctx.add_signer(&key)?;
            let mut output = Vec::new();
            let signature = ctx.sign_detached(to_sign, &mut output);
            if let Err(e) = signature {
                return Err(Error::Gpg(e));
            }

            Ok(String::from_utf8(output)?)
        }
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
            let fpt_hex = s
                .fingerprint()
                .map_err(|e| VerificationError::InfrastructureError(format!("{e:?}")))?;

            let raw_fpt = <[u8; 20]>::from_hex(fpt_hex)
                .map_err(|e| VerificationError::InfrastructureError(format!("{e:?}")))?;

            if !valid_signing_keys.contains(&raw_fpt) {
                let key = ctx.get_key(fpt_hex).unwrap();
                let primary_key = key.primary_key().unwrap();
                let fpr = primary_key.fingerprint().unwrap();
                let fpr = <[u8; 20]>::from_hex(fpr)
                    .map_err(|e| VerificationError::InfrastructureError(format!("{e:?}")))?;
                if !valid_signing_keys.contains(&fpr) {
                    return Err(VerificationError::SignatureFromWrongRecipient);
                }
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
    fn try_passphrases(
        &self,
        recipients: &[Recipient],
        passphrase_provider: Option<Handler>,
        max_tries: Option<u8>,
    ) -> Result<Option<Recipient>> {
        if let Some(mut passphrase_provider) = passphrase_provider {
            let mut ctx = passphrase_provider.create_context()?;
            for recipient in recipients.iter() {
                if recipient.not_usable {
                    continue;
                }
                *(passphrase_provider
                    .last_tried_recipient
                    .clone()
                    .lock()
                    .unwrap()) = Some(recipient.clone());
                let k = ctx.locate_key(recipient.key_id.clone()).unwrap();
                let mut encrypted = Vec::new();
                ctx.encrypt(vec![&k], "", &mut encrypted)?;
                let max_tries = max_tries.unwrap_or(1);
                for i in 0..max_tries {
                    let decryption_res = ctx.decrypt(&mut encrypted, &mut Vec::new());
                    match decryption_res {
                        Ok(_decryption_res) => {
                            *passphrase_provider.failure_count.lock().unwrap() = 0;
                            passphrase_provider.err_msg.lock().unwrap().take();
                            return Ok(Some(recipient.clone()));
                        }
                        Err(e) => match gpgme::Error::from_code(e.code()) {
                            gpgme::Error::BAD_PASSPHRASE => {
                                *(passphrase_provider.err_msg.clone().lock().unwrap()) = Some(
                                    format!("Wrong passphrase, {} tries left", max_tries - 1 - i),
                                );
                                continue;
                            }
                            gpgme::Error::NO_SECKEY => {
                                break;
                            }
                            _ => {
                                *passphrase_provider.failure_count.lock().unwrap() = 0;
                                passphrase_provider.err_msg.lock().unwrap().take();
                                return Ok(None);
                            }
                        },
                    }
                }
                *passphrase_provider.failure_count.lock().unwrap() = 0;
                passphrase_provider.err_msg.lock().unwrap().take();
            }
            return Ok(None);
        } else {
            let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
            ctx.set_pinentry_mode(gpgme::PinentryMode::Ask)?;
            for recipient in recipients.iter() {
                if recipient.not_usable {
                    continue;
                }
                let k = ctx.locate_key(recipient.key_id.clone())?;

                let mut encrypted = Vec::new();
                let plaintext = "";
                ctx.encrypt(vec![&k], plaintext, &mut encrypted)?;
                let decryption_res = ctx.decrypt(&mut encrypted, &mut Vec::new());
                if let Ok(_decryption_res) = decryption_res {
                    return Ok(Some(recipient.clone()));
                }
            }
            return Ok(None);
        }
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
