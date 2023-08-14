use hex::FromHex;
use std::str::FromStr;
use strum_macros::{Display, EnumString};

use rpass::{
    crypto::{self, CryptoImpl},
    git::{pull, push},
    pass::{self, Error, PasswordEntry},
    pass::{
        all_recipients_from_stores, OwnerTrustLevel, PasswordStore, Recipient, SignatureStatus,
    },
};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process,
    rc::Rc,
    sync::{Arc, Mutex},
    thread, time,
};
/// The 'pointer' to the current PasswordStore is of this convoluted type.
type PasswordStoreType = Arc<Mutex<Arc<Mutex<PasswordStore>>>>;
/// The list of stores that the user have.
type StoreListType = Arc<Mutex<Vec<Arc<Mutex<PasswordStore>>>>>;
fn copy(id: &str, store: PasswordStoreType) -> pass::Result<String> {
    println!("given id {}", id);
    let entry = match get_entries(id, store.clone()) {
        Ok(entries) => entries[0].clone(),
        Err(err) => {
            return Err(err);
        }
    };
    let decrypted = entry.secret(&*store.lock()?.lock()?, None);
    if decrypted.is_ok() {
        // println!("{}", decrypted.as_ref().unwrap());
    } else {
        // println!("{}", decrypted.as_ref().unwrap_err());
    }
    return decrypted;
}
/// Validates the config for password stores.
/// Returns a list of paths that the new store wizard should be run for
fn validate_stores_config(settings: &config::Config, home: &Option<PathBuf>) -> Vec<PathBuf> {
    let mut incomplete_stores: Vec<PathBuf> = vec![];

    let stores_res = settings.get("stores");
    if let Ok(stores) = stores_res {
        let stores: HashMap<String, config::Value> = stores;

        for store_name in stores.keys() {
            let store: HashMap<String, config::Value> = stores
                .get(store_name)
                .unwrap()
                .clone()
                .into_table()
                .unwrap();

            let password_store_dir_opt = store.get("path");

            if let Some(p) = password_store_dir_opt {
                let p_path = PathBuf::from(p.clone().into_str().unwrap());
                let gpg_id = p_path.clone().join(".gpg-id");

                if !p_path.exists() || !gpg_id.exists() {
                    incomplete_stores.push(PathBuf::from(p.clone().into_str().unwrap()));
                }
            }
        }
    } else if incomplete_stores.is_empty() && home.is_some() {
        incomplete_stores.push(home.clone().unwrap().join(".password_store"));
    }

    incomplete_stores
}
fn get_stores(config: &config::Config, home: &Option<PathBuf>) -> pass::Result<Vec<PasswordStore>> {
    let mut final_stores: Vec<PasswordStore> = vec![];
    let stores_res = config.get("stores");
    if let Ok(stores) = stores_res {
        let stores: HashMap<String, config::Value> = stores;

        for store_name in stores.keys() {
            let store: HashMap<String, config::Value> = stores
                .get(store_name)
                .unwrap()
                .clone()
                .into_table()
                .unwrap();

            let password_store_dir_opt = store.get("path");
            let mut valid_signing_keys_opt = store.get("valid_signing_keys");
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
                let style_path_opt = match store.get("style_path") {
                    Some(path) => match path.clone().into_str() {
                        Ok(p) => Some(PathBuf::from(p)),
                        Err(_err) => None,
                    },
                    None => None,
                };

                let pgp_impl = match store.get("pgp") {
                    Some(pgp_str) => CryptoImpl::try_from(pgp_str.clone().into_str()?.as_str()),
                    None => Ok(CryptoImpl::GpgMe),
                }?;

                let own_fingerprint = store.get("own_fingerprint");
                let own_fingerprint = match own_fingerprint {
                    None => None,
                    Some(k) => match k.clone().into_str() {
                        Err(_) => None,
                        Ok(key) => match <[u8; 20]>::from_hex(key) {
                            Err(_) => None,
                            Ok(fp) => Some(fp),
                        },
                    },
                };

                final_stores.push(PasswordStore::new(
                    store_name,
                    &password_store_dir,
                    &valid_signing_keys,
                    home,
                    &style_path_opt,
                    &pgp_impl,
                    &own_fingerprint,
                )?);
            }
        }
    } else if final_stores.is_empty() && home.is_some() {
        let default_path = home.clone().unwrap().join(".password_store");
        if default_path.exists() {
            final_stores.push(PasswordStore::new(
                "default",
                &Some(default_path),
                &None,
                home,
                &None,
                &CryptoImpl::GpgMe,
                &None,
            )?);
        }
    }

    Ok(final_stores)
}
fn main() -> pass::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open("/Users/JANG/rpass_test.log")
        .expect("Failed to open file");
    writeln!(
        &mut f,
        "{}",
        serde_json::to_string(&"main called, logged before entering message listening loop")
            .unwrap()
    );
    let received_message_res = get_message();
    if received_message_res.is_err() {
        // continue;
    }
    let received_message = received_message_res.unwrap();
    writeln!(
        &mut f,
        "{}",
        serde_json::to_string(&received_message).unwrap()
    )
    .unwrap();
    let command = parse_message(received_message.clone()).unwrap();
    if let Command::Init {
        remote,
        home_dir,
        store_dir,
        password_store_signing_key,
    } = command
    {
        let home = {
            if home_dir.is_some() {
                Some(PathBuf::from(home_dir.unwrap()))
            } else {
                match std::env::var("HOME") {
                    Err(_) => None,
                    Ok(home_path) => Some(PathBuf::from(home_path)),
                }
            }
        };
        let password_store_dir = {
            if store_dir.is_some() {
                Some(store_dir.unwrap())
            } else {
                match std::env::var("PASSWORD_STORE_DIR") {
                    Err(_) => None,
                    Ok(password_store_dir) => Some(password_store_dir),
                }
            }
        };
        let password_store_signing_key = {
            if password_store_signing_key.is_some() {
                Some(password_store_signing_key.unwrap())
            } else {
                match std::env::var("PASSWORD_STORE_SIGNING_KEY") {
                    Err(_) => None,
                    // Err(_) => Some("F40FBF4B025339DEA21D3D2D3E1DDD1257F3A8F1".to_owned()),
                    Ok(password_store_signing_key) => Some(password_store_signing_key),
                }
            }
        };
        let xdg_data_home = match std::env::var("XDG_DATA_HOME") {
            Err(_) => match &home {
                Some(home_path) => home_path.join(".local"),
                None => {
                    eprintln!("{}", "No home directory set");
                    process::exit(1);
                }
            },
            Ok(data_home_path) => PathBuf::from(data_home_path),
        };

        let config_res = {
            let xdg_config_home = match std::env::var("XDG_CONFIG_HOME") {
                Err(_) => None,
                Ok(config_home_path) => Some(PathBuf::from(config_home_path)),
            };

            pass::read_config(
                &password_store_dir,
                &password_store_signing_key,
                &home,
                &xdg_config_home,
            )
        };
        if let Err(err) = config_res {
            eprintln!("Error {err}");
            process::exit(1);
        }
        let (config, config_file_location) = config_res.unwrap();

        let stores = get_stores(&config, &home);
        if let Err(err) = stores {
            eprintln!("Error {err}");
            process::exit(1);
        }

        let stores: StoreListType = Arc::new(Mutex::new(
            stores
                .unwrap()
                .into_iter()
                .map(|s| Arc::new(Mutex::new(s)))
                .collect(),
        ));

        if !config_file_location.exists() && stores.lock()?.len() == 1 {
            let mut config_file_dir = config_file_location.clone();
            config_file_dir.pop();
            if let Err(err) = std::fs::create_dir_all(config_file_dir) {
                eprintln!("Error {err}");
                process::exit(1);
            }
            if let Err(err) = pass::save_config(stores.clone(), &config_file_location) {
                eprintln!("Error {err}");
                process::exit(1);
            }
        }

        let store: PasswordStoreType = Arc::new(Mutex::new(stores.lock()?[0].clone()));
        #[allow(clippy::significant_drop_in_scrutinee)]
        for ss in stores.lock()?.iter() {
            if ss.lock()?.get_name() == "default" {
                let mut s = store.lock()?;
                *s = ss.clone();
            }
        }
        let res = store.lock()?.lock()?.reload_password_list();
        if let Err(err) = res {
            eprintln!("Error {err}");
            process::exit(1);
        }

        // verify that the git config is correct
        if !store.lock()?.lock()?.has_configured_username() {
            process::exit(1);
        }

        for password in &store.lock()?.lock()?.passwords {
            if password.is_in_git == pass::RepositoryStatus::NotInRepo {
                process::exit(1);
            }
        }
        // This construction is to make sure that the password list is populated when the program starts
        // it would be better to signal this somehow from the library, but that got tricky
        thread::sleep(time::Duration::from_millis(200));
        listen_to_native_messaging(&store);
        Ok(())
    } else {
        Err(Error::Generic(
            &"The first message json must have 'init' as key and initialization values as its value"
        ))
    }
}
fn get_message() -> Result<serde_json::Value, ()> {
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open("/Users/JANG/rpass_test.log")
        .expect("Failed to open file");
    let mut raw_length = [0; 4];
    // io::stdin().read_exact(&mut raw_length)?;
    if let Err(read_length_res) = io::stdin().read_exact(&mut raw_length) {
        return Err(());
    }
    let message_length = u32::from_le_bytes(raw_length);
    let mut message = vec![0; message_length as usize];
    io::stdin()
        .read_exact(&mut message)
        .expect("Failed to read message content");
    writeln!(
        &mut f,
        "message: {}",
        serde_json::to_string(&message).unwrap()
    )
    .unwrap();
    let parsed = serde_json::from_slice(message.as_slice());
    if let Err(err) = parsed {
        return Err(());
    } else {
        return Ok(parsed.unwrap());
    }
}

/// Encode a message for transmission, given its content.
fn encode_message<T: Serialize>(message_content: &T) -> Vec<u8> {
    let encoded_content = serde_json::to_vec(message_content).expect("Failed to encode JSON");
    let encoded_length = (encoded_content.len() as u32).to_le_bytes();
    [&encoded_length, encoded_content.as_slice()].concat()
}

/// Send an encoded message to stdout
fn send_message(encoded_message: &[u8]) {
    eprint!("encoded_message: {:?}", encoded_message);
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open("/Users/JANG/rpass_test.log")
        .expect("Failed to open file");
    writeln!(
        &mut f,
        "{}",
        serde_json::to_string(&format!("encoded_message: {:?}", encoded_message)).unwrap()
    )
    .unwrap();
    io::stdout()
        .write_all(encoded_message)
        .expect("Failed to write to stdout");
    io::stdout().flush().expect("Failed to flush stdout");
}
#[derive(Serialize, Deserialize, Debug, EnumString, Display)]
#[serde(tag = "type")]
//path: store/address
//username: mostly user email
//file structure: store/address/username.gpg
enum Command {
    //get password
    #[serde(rename = "get")]
    #[strum(serialize = "get", serialize = "r")]
    Get {
        username: String,
        passphrase: Option<String>,
        path: String,
    },
    //set password of existing password entry
    #[serde(rename = "edit")]
    #[strum(serialize = "edit", serialize = "e")]
    Edit {
        username: String,
        passphrase: Option<String>,
        path: String,
        value: Option<String>,
    },
    #[serde(rename = "edit_username")]
    #[strum(serialize = "edit_username", serialize = "u")]
    EditUserName {
        username: String,
        passphrase: Option<String>,
        path: String,
        value: Option<String>,
    },
    //create a new password entry with passed password
    #[serde(rename = "create")]
    #[strum(serialize = "create", serialize = "c")]
    Create {
        username: String,
        // passphrase: Option<String>,
        path: String,
        value: Option<String>,
    },
    //generate a new password(no saving)
    #[serde(rename = "generate")]
    #[strum(serialize = "generate", serialize = "g")]
    Generate {},
    //delete password entry
    #[serde(rename = "delete")]
    #[strum(serialize = "delete", serialize = "d")]
    Delete {
        username: String,
        passphrase: Option<String>,
        path: String,
    },
    #[serde(rename = "pull")]
    #[strum(serialize = "pull", serialize = "p")]
    Pull { remote: Option<String> },
    #[serde(rename = "push")]
    #[strum(serialize = "push", serialize = "P")]
    Push { remote: Option<String> },
    #[serde(rename = "init")]
    #[strum(serialize = "init", serialize = "i")]
    Init {
        remote: Option<String>,
        home_dir: Option<String>,
        store_dir: Option<String>,
        password_store_signing_key: Option<String>,
    },
}

fn parse_message(message: serde_json::Value) -> Result<Command, ()> {
    let command: Command = serde_json::from_value::<Command>(message.clone()).expect(&format!(
        "Failed to parse JSON: {:?}",
        &(message.to_string())
    ));
    Ok(command)
}
fn execute_command(command: Command, store: &PasswordStoreType) -> pass::Result<()> {
    let mut f = {
        if let Ok(f) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open("/Users/JANG/rpass_test.log")
        {
            Some(f)
        } else {
            None
        }
    };
    if let Some(f) = &mut f {
        let command_args = &format!("command: {:?}", command.to_string(),);
        if let Err(err) = writeln!(f, "{}", command_args) {
            eprint!("Failed to write logs to file: {:?}", err);
        }
    }
    match command {
        Command::Get {
            username,
            passphrase,
            path,
        } => {
            let encrypted_password = &search(&store.clone(), &(path + "/" + &username)).unwrap()[0];
            let store = store.lock()?;
            let unlocked_store = &*store.lock()?;
            let password = &encrypted_password
                .secret(unlocked_store, passphrase)
                .unwrap_or("failed to decrypt password".to_string());
            send_message(&encode_message(&format!("password: {password}")));
            return Ok(());
        }
        Command::Create {
            username,
            path,
            value,
        } => {
            let value = value.unwrap();
            create_password_entry(
                Some(value),
                Some(path + "/" + &username),
                store.clone(),
                None,
            )?;
            return Ok(());
        }
        Command::Edit {
            username,
            passphrase,
            path,
            value,
        } => {
            let value = value.unwrap();
            change_password(&value, &(path + "/" + &username), store.clone(), passphrase)
                .expect("Failed to change password");
            Ok(())
        }
        Command::EditUserName {
            username,
            passphrase,
            path,
            value,
        } => {
            let value = value.unwrap();
            do_rename_file(
                &(path.clone() + "/" + &username),
                &(path.clone() + "/" + &value),
                store.clone(),
                passphrase,
            )
            .expect("Failed to rename file");
            Ok(())
        }
        Command::Delete {
            username,
            passphrase,
            path,
        } => {
            delete_password_entry(store.clone(), &(path + "/" + &username), passphrase)?;
            Ok(())
        }
        _ => Ok(()),
    }
}

fn listen_to_native_messaging(store: &PasswordStoreType) -> pass::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open("/Users/JANG/rpass_test.log")
        .expect("Failed to open file");
    writeln!(
        &mut f,
        "{}",
        serde_json::to_string(&"main called, logged before entering message listening loop")
            .unwrap()
    );
    loop {
        let received_message_res = get_message();
        if received_message_res.is_err() {
            continue;
        }
        let received_message = received_message_res.unwrap();
        writeln!(
            &mut f,
            "{}",
            serde_json::to_string(&received_message).unwrap()
        )
        .unwrap();
        let command = parse_message(received_message.clone()).unwrap();
        execute_command(command, &store);
    }
}
fn do_rename_file(
    old_name: &str,
    new_name: &str,
    store: PasswordStoreType,
    passphrase: Option<String>,
) -> pass::Result<()> {
    let res = store
        .lock()?
        .lock()?
        .rename_file(old_name, &new_name, passphrase);
    Ok(())
}

fn create_password_entry(
    password: Option<String>,
    path: Option<String>,
    store: PasswordStoreType,
    note: Option<String>,
) -> pass::Result<PasswordEntry> {
    if password.is_none() {
        return Err(pass::Error::Generic(
            "No password is given. Password must be passed to create_password_entry",
        ));
    }
    let mut password = password.unwrap();
    if password.is_empty() {
        return Err(pass::Error::Generic(
            "Password is empty, not saving anything",
        ));
    }
    if path.is_none() {
        return Err(pass::Error::Generic(
            "No path given. Path must be passed to create_password_entry",
        ));
    }
    let path = path.unwrap();
    if path.is_empty() {
        return Err(pass::Error::Generic("Path is empty, not saving anything"));
    }

    if let Some(note) = note {
        password = format!("{password}\n{note}");
    }
    if password.contains("otpauth://") {
        eprint!("It seems like you are trying to save a TOTP code to the password store. This will reduce your 2FA solution to just 1FA, do you want to proceed?");
    }
    new_password_save(path.as_ref(), password.as_ref(), store)
}
fn new_password_save(
    path: &str,
    password: &str,
    store: PasswordStoreType,
) -> pass::Result<PasswordEntry> {
    let entry = store
        .lock()?
        .lock()?
        .new_password_file(path.as_ref(), password.as_ref());
    entry
}

fn change_password(
    password: &str,
    path: &str,
    store: PasswordStoreType,
    passphrase: Option<String>,
) -> pass::Result<()> {
    eprintln!("change_password called, path: {path}, password: {password}");
    let password_entry_opt = get_entry(&*store.lock()?.lock()?, path);
    if password_entry_opt.is_none() {
        return Err("No password entry found".into());
    }
    let password_entry = password_entry_opt.unwrap();
    let r = password_entry.update_with_passphrase(
        password.to_string(),
        &*store.lock()?.lock()?,
        passphrase,
    );
    if r.is_err() {
        eprint!("Failed to update password: {:?}", r.as_ref().unwrap_err());
    }
    return r;
}
fn get_entries(query: &str, store: PasswordStoreType) -> pass::Result<Vec<PasswordEntry>> {
    let entries = pass::search(&*store.lock()?.lock()?, &String::from(query));
    if entries.len() == 0 {
        return Err("No entries found".into());
    }
    Ok(entries)
}
fn search(store: &PasswordStoreType, query: &str) -> pass::Result<Vec<PasswordEntry>> {
    let first_locked = store.lock()?;
    let locked_store = first_locked.lock()?;
    let passwords = &*locked_store.passwords;
    fn normalized(s: &str) -> String {
        s.to_lowercase()
    }
    fn matches(s: &str, q: &str) -> bool {
        normalized(s).as_str().contains(normalized(q).as_str())
    }
    let matching = passwords.iter().filter(|p| matches(&p.name, query));
    let result = matching.cloned().collect();
    Ok(result)
}
pub fn get_entry(store: &PasswordStore, path: &str) -> Option<PasswordEntry> {
    let passwords = &store.passwords;
    fn normalized(s: &str) -> String {
        s.to_lowercase()
    }
    fn matches(s: &str, p: &str) -> bool {
        normalized(s).as_str() == normalized(p).as_str()
    }
    let matching = passwords.iter().find(|p| matches(&p.name, path)).cloned();
    return matching;
}
fn delete_password_entry(
    store: PasswordStoreType,
    path: &str,
    passphrase: Option<String>,
) -> pass::Result<()> {
    let password_entry_opt = get_entry(&*store.lock()?.lock()?, path);
    if password_entry_opt.is_none() {
        return Err("No password entry found".into());
    }
    let password_entry = password_entry_opt.unwrap();
    password_entry.delete_file_passphrase(&*store.lock()?.lock()?, passphrase)
}
