use std::fmt::Debug;
use strum_macros::EnumString;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use strum_macros::Display;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Display, EnumString)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum DataFieldType {
    PortID,
    Meta,
    ErrorType,
    InitError,
    NativeAppConnectionError,
    CanSign,
    CanEncrypt,
    Keys,
    KeyHasSecret,
    KeyID,
    KeyFingerprint,
    KeyUserID,
    KeyUsable,
    KeyUsername,
    HomeDir,
    IsRepo,
    SubStore,
    IsDefault,
    DefaultStoreID,
    DefaultStoreAvailable,
    ContentScript,
    Request,
    SigningKey,
    StoreDir,
    StoreID,
    PrevStoreID,
    StorePath,
    ResourceID,
    UserID,
    Username,
    Passphrase,
    Password,
    Note,
    Recipient,
    ValidSignerList,
    RepoSigningKey,
    CustomField,
    CustomFieldPrefix,
    Domain,
    Path,
    Resource,
    Query,
    Value,
    Verified,
    Error,
    ErrorMessage,
    ErrorCode,
    ErrorSource,
    Update,
    UpdateLog,
    Delete,
    Create,
    Search,
    Fetch,
    Login,
    Logout,
    Status,
    Acknowledgement,
    Data,
    CreateStore,
    StoreIDList,
    ParentStoreId,
}

// impl fmt::Display for DataFieldType {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "{}", serde_json::to_string(&self).unwrap())
//     }
// }

// impl<T> From<T> for DataFieldType
// where
//     T: AsRef<str> + Debug,
// {
//     fn from(value: T) -> Self {}
// }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateLog {
    pub field: DataFieldType,
    pub old: Value,
    pub new: Value,
}

impl UpdateLog {
    pub fn new(field: DataFieldType, old: Value, new: Value) -> Self {
        UpdateLog { field, old, new }
    }
}
