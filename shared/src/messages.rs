use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Register(Register),
    RegisterOk,
    RequestChallenge(RequestChallenge),
    Challenge(Challenge),
    Login(Login),
    LoginOk(LoginOk),
    Upload(Upload),
    UploadOk,
    List(List),
    ListResponse(ListResponse),
    Download(Download),
    DownloadResponse(DownloadResponse),
    Delete(Delete),
    DeleteOk,
    Error(Error),
}

impl Message {
    pub fn type_byte(&self) -> u8 {
        match self {
            Message::Register(_)          => 0x01,
            Message::RegisterOk           => 0x02,
            Message::RequestChallenge(_)  => 0x03,
            Message::Challenge(_)         => 0x04,
            Message::Login(_)             => 0x05,
            Message::LoginOk(_)           => 0x06,
            Message::Upload(_)            => 0x07,
            Message::UploadOk             => 0x08,
            Message::List(_)              => 0x09,
            Message::ListResponse(_)       => 0x0A,
            Message::Download(_)          => 0x0B,
            Message::DownloadResponse(_)  => 0x0C,
            Message::Delete(_)            => 0x0D,
            Message::DeleteOk             => 0x0E,
            Message::Error(_)             => 0xFF,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Register {
    pub username: String,
    pub salt: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestChallenge {
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub nonce: Vec<u8>,
    pub salt: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Login {
    pub username: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginOk {
    pub session_token: Vec<u8>,
}

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