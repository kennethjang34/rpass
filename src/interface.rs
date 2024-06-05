use core::fmt;
use serde_variant::to_variant_name;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
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
    UpdatedFields,
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
impl fmt::Display for DataFieldType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", to_variant_name(&self).unwrap())
    }
}

impl From<Value> for DataFieldType {
    fn from(value: Value) -> Self {
        let s = value.as_str().unwrap();
        serde_json::from_str(s).unwrap()
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateLog {
    pub field: DataFieldType,
    pub old: Value,
    pub new: Value,
}
