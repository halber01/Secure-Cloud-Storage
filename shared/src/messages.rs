use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // OPAQUE Registration (3 messages)
    OpaqueRegStart(OpaqueRegStart),   // 0x01  C→S  blinded password element
    OpaqueRegResp(OpaqueRegResp),     // 0x02  S→C  server OPAQUE response
    OpaqueRegFinish(OpaqueRegFinish), // 0x03  C→S  encrypted envelope record
    RegisterOk,                       // 0x04  S→C  registration success

    // OPAQUE Login (3 messages)
    OpaqueLoginStart(OpaqueLoginStart),   // 0x05  C→S  credential request
    OpaqueLoginResp(OpaqueLoginResp),     // 0x06  S→C  credential response
    OpaqueLoginFinish(OpaqueLoginFinish), // 0x07  C→S  key exchange finalization
    LoginOk(LoginOk),                     // 0x08  S→C  session token

    // File operations
    Upload(Upload),                     // 0x09  C→S
    UploadOk,                           // 0x0A  S→C
    List(List),                         // 0x0B  C→S
    ListResponse(ListResponse),         // 0x0C  S→C
    Download(Download),                 // 0x0D  C→S
    DownloadResponse(DownloadResponse), // 0x0E  S→C
    Delete(Delete),                     // 0x0F  C→S
    DeleteOk,                           // 0x10  S→C
    Error(Error),                       // 0xFF  S→C
}

impl Message {
    pub fn type_byte(&self) -> u8 {
        match self {
            Message::OpaqueRegStart(_) => 0x01,
            Message::OpaqueRegResp(_) => 0x02,
            Message::OpaqueRegFinish(_) => 0x03,
            Message::RegisterOk => 0x04,
            Message::OpaqueLoginStart(_) => 0x05,
            Message::OpaqueLoginResp(_) => 0x06,
            Message::OpaqueLoginFinish(_) => 0x07,
            Message::LoginOk(_) => 0x08,
            Message::Upload(_) => 0x09,
            Message::UploadOk => 0x0A,
            Message::List(_) => 0x0B,
            Message::ListResponse(_) => 0x0C,
            Message::Download(_) => 0x0D,
            Message::DownloadResponse(_) => 0x0E,
            Message::Delete(_) => 0x0F,
            Message::DeleteOk => 0x10,
            Message::Error(_) => 0xFF,
        }
    }
}

// ── OPAQUE Registration ──────────────────────────────────────────────────────

/// Step 1 of OPAQUE registration.
/// Client blinds the password and sends the serialized RegistrationRequest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueRegStart {
    pub username: String,
    pub request: Vec<u8>,
}

/// Step 2 of OPAQUE registration.
/// Server returns the serialized RegistrationResponse (server element + server public key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueRegResp {
    pub response: Vec<u8>,
}

/// Step 3 of OPAQUE registration.
/// Client sends the serialized RegistrationUpload (encrypted envelope).
/// Also includes the Ed25519 public key derived from export_key for file-op signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueRegFinish {
    pub username: String,
    pub record: Vec<u8>,
    pub public_key: Vec<u8>,
}

// ── OPAQUE Login ─────────────────────────────────────────────────────────────

/// Step 1 of OPAQUE login.
/// Client sends the serialized CredentialRequest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueLoginStart {
    pub username: String,
    pub request: Vec<u8>,
}

/// Step 2 of OPAQUE login.
/// Server sends the serialized CredentialResponse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueLoginResp {
    pub response: Vec<u8>,
}

/// Step 3 of OPAQUE login.
/// Client sends the serialized KeyExchange finalization message.
/// If the password was wrong, the client never sends this — it returns an error locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueLoginFinish {
    pub username: String,
    pub finalization: Vec<u8>,
}

/// Login success. Server issues a session token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginOk {
    pub session_token: Vec<u8>,
}

// ── File operations (structs unchanged) ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upload {
    pub session_token: Vec<u8>,
    pub file_id: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub encrypted_metadata: Vec<u8>,
    pub version: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct List {
    pub session_token: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse {
    pub list: Vec<FileEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub file_id: Vec<u8>,
    pub encrypted_metadata: Vec<u8>,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Download {
    pub session_token: Vec<u8>,
    pub file_id: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadResponse {
    pub ciphertext: Vec<u8>,
    pub encrypted_metadata: Vec<u8>,
    pub version: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delete {
    pub session_token: Vec<u8>,
    pub file_id: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Error {
    pub code: u8,
    pub message: String,
}
