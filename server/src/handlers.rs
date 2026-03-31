use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use rand::RngCore;
use rand::rngs::OsRng;
use crate::store::{Store, UserRecord, FileRecord};
use shared::messages::*;

/// Central dispatch — matches incoming message to the right handler
pub async fn handle(msg: Message, store: &Store) -> Message {
    match msg {
        Message::Register(r)   => handle_register(r, store),
        Message::RequestChallenge(r) => handle_challenge(r, store),
        Message::Login(r)      => handle_login(r, store),
        Message::Upload(r)     => handle_upload(r, store),
        Message::List(r)       => handle_list(r, store),
        Message::Download(r)   => handle_download(r, store),
        Message::Delete(r)     => handle_delete(r, store),
        Message::GetVersion(r)   => handle_get_version(r, store),
        _ => error(0x07, "Unexpected message type"),
    }
}

// Helper
fn error(code: u8, msg: &str) -> Message {
    Message::Error(Error {
        code,
        message: msg.to_string(),
    })
}

fn handle_register(req: Register, store: &Store) -> Message {
    if store.register_user(req.username.clone(), UserRecord {
        salt: req.salt,
        public_key: req.public_key,
    }) {
        println!("[REGISTER] New user: '{}'", req.username);
        Message::RegisterOk
    } else {
        println!("[REGISTER] Failed - user exists: '{}'", req.username);
        error(0x02, "Username already exists")
    }
}

fn handle_challenge(req: RequestChallenge, store: &Store) -> Message {
    // User must exist before we issue a challenge
    println!("[CHALLENGE] Issued for user: '{}'", req.username);
    let user = match store.get_user(&req.username) {
        Some(u) => u,
        None => return error(0x03, "User not found"),
    };

    // Generate a fresh random nonce. Only one time use
    let mut nonce = vec![0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    store.store_challenge(req.username, nonce.clone());

    Message::Challenge(Challenge {
        nonce,
        salt: user.salt,
    })
}

fn handle_login(req: Login, store: &Store) -> Message {
    // Consume the challenge — prevents replay
    let nonce = match store.take_challenge(&req.username) {
        Some(n) => n,
        None => return error(0x01, "No pending challenge"),
    };

    // Get the stored public key
    let user = match store.get_user(&req.username) {
        Some(u) => u,
        None => return error(0x03, "User not found"),
    };

    // Verify Ed25519 signature over "login:" || nonce
    let mut msg = b"login:".to_vec();
    msg.extend_from_slice(&nonce);
    let ok = verify_signature(&user.public_key, &msg, &req.signature);
    if !ok {
        return error(0x04, "Invalid signature");
    }

    // Issue session token
    let mut token = vec![0u8; 32];
    OsRng.fill_bytes(&mut token);
    store.create_session(token.clone(), req.username);

    Message::LoginOk(LoginOk { session_token: token })
}

fn handle_upload(req: Upload, store: &Store) -> Message {
    // Authenticate
    let username = match store.resolve_session(&req.session_token) {
        Some(u) => u,
        None => return error(0x01, "Unauthorized"),
    };

    // Verify Ed25519 signature over file_id || version || ciphertext
    let user = store.get_user(&username).unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(&req.file_id);
    msg.extend_from_slice(&req.version.to_le_bytes());
    msg.extend_from_slice(&req.ciphertext);
    if !verify_signature(&user.public_key, &msg, &req.signature) {
        return error(0x04, "Invalid signature");
    }

    println!("[UPLOAD] user='{}' file_id='{}' version={}",
             username,
             hex::encode(&req.file_id),
             req.version
    );
    // Store: put_file enforces version monotonicity
    match store.put_file(username, req.file_id, FileRecord {
        ciphertext: req.ciphertext,
        encrypted_metadata: req.encrypted_metadata,
        version: req.version,
        signature: req.signature,
    }) {
        Ok(()) => Message::UploadOk,
        Err(e) => error(0x05, &e),
    }
}

fn handle_list(req: List, store: &Store) -> Message {
    let username = match store.resolve_session(&req.session_token) {
        Some(u) => u,
        None => return error(0x01, "Unauthorized"),
    };

    let entries = store
        .list_files(&username)
        .into_iter()
        .map(|(file_id, encrypted_metadata, version)| FileEntry {
            file_id,
            encrypted_metadata,
            version,
        })
        .collect();

    Message::ListResponse(ListResponse { list: entries })
}

fn handle_download(req: Download, store: &Store) -> Message {
    let username = match store.resolve_session(&req.session_token) {
        Some(u) => u,
        None => return error(0x01, "Unauthorized"),
    };
    println!("[DOWNLOAD] user='{}' file_id='{}'",
             username,
             hex::encode(&req.file_id)
    );
    match store.get_file(&username, &req.file_id) {
        Some(rec) => Message::DownloadResponse(DownloadResponse {
            ciphertext: rec.ciphertext,
            encrypted_metadata: rec.encrypted_metadata,
            version: rec.version,
            signature: rec.signature,
        }),
        None => error(0x06, "File not found"),
    }
}

fn handle_delete(req: Delete, store: &Store) -> Message {
    let username = match store.resolve_session(&req.session_token) {
        Some(u) => u,
        None => return error(0x01, "Unauthorized"),
    };

    // Verify signature over "delete:" || file_id
    let user = store.get_user(&username).unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(b"delete:");
    msg.extend_from_slice(&req.file_id);
    if !verify_signature(&user.public_key, &msg, &req.signature) {
        return error(0x04, "Invalid signature");
    }

    if store.delete_file(&username, &req.file_id) {
        Message::DeleteOk
    } else {
        error(0x06, "File not found")
    }
}

fn handle_get_version(req: GetVersion, store: &Store) -> Message {
    let username = match store.resolve_session(&req.session_token) {
        Some(u) => u,
        None => return error(0x01, "Unauthorized"),
    };
    let version = store
        .get_file(&username, &req.file_id)
        .map(|f| f.version)
        .unwrap_or(0);
    Message::VersionResponse(VersionResponse{ version })
}

// Signature verification helper
fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let pk_bytes: [u8; 32] = match public_key.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes: [u8; 64] = match signature.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    use crate::store::Store;

    /// Helper: registers alice and returns her signing key
    fn setup_alice(store: &Store) -> SigningKey {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        store.register_user("alice".to_string(), UserRecord {
            salt: vec![0u8; 16],
            public_key,
        });
        signing_key
    }

    /// Helper: logs alice in and returns her session token
    async fn login_alice(store: &Store, signing_key: &SigningKey) -> Vec<u8> {
        // get challenge
        let resp = handle(Message::RequestChallenge(RequestChallenge {
            username: "alice".to_string(),
        }), store).await;

        let nonce = match resp {
            Message::Challenge(c) => c.nonce,
            _ => panic!("Expected challenge"),
        };

        // sign it
        let mut msg = b"login:".to_vec();
        msg.extend_from_slice(&nonce);
        let signature = signing_key.sign(&msg).to_bytes().to_vec();

        let resp = handle(Message::Login(Login {
            username: "alice".to_string(),
            signature,
        }), store).await;

        match resp {
            Message::LoginOk(l) => l.session_token,
            _ => panic!("Expected LoginOk"),
        }
    }

    #[tokio::test]
    async fn test_register_ok() {
        let store = Store::new();
        let resp = handle(Message::Register(Register {
            username: "alice".to_string(),
            salt: vec![0u8; 16],
            public_key: vec![0u8; 32],
        }), &store).await;
        assert!(matches!(resp, Message::RegisterOk));
    }

    #[tokio::test]
    async fn test_register_duplicate_fails() {
        let store = Store::new();
        let req = Register {
            username: "alice".to_string(),
            salt: vec![0u8; 16],
            public_key: vec![0u8; 32],
        };
        handle(Message::Register(req.clone()), &store).await;
        let resp = handle(Message::Register(req), &store).await;
        assert!(matches!(resp, Message::Error(_)));
    }

    #[tokio::test]
    async fn test_login_wrong_signature_fails() {
        let store = Store::new();
        setup_alice(&store);

        // get challenge first
        handle(Message::RequestChallenge(RequestChallenge {
            username: "alice".to_string(),
        }), &store).await;

        // send wrong signature
        let resp = handle(Message::Login(Login {
            username: "alice".to_string(),
            signature: vec![0u8; 64], // garbage signature
        }), &store).await;

        assert!(matches!(resp, Message::Error(_)));
    }

    #[tokio::test]
    async fn test_upload_and_download() {
        let store = Store::new();
        let signing_key = setup_alice(&store);
        let token = login_alice(&store, &signing_key).await;

        let file_id = vec![1u8; 32];
        let ciphertext = vec![2u8; 64];

        // build upload signature
        let mut msg = Vec::new();
        msg.extend_from_slice(&file_id);
        msg.extend_from_slice(&1u64.to_le_bytes());
        msg.extend_from_slice(&ciphertext);
        let signature = signing_key.sign(&msg).to_bytes().to_vec();

        // upload
        let resp = handle(Message::Upload(Upload {
            session_token: token.clone(),
            file_id: file_id.clone(),
            ciphertext: ciphertext.clone(),
            encrypted_metadata: vec![3u8; 32],
            version: 1,
            signature,
        }), &store).await;
        assert!(matches!(resp, Message::UploadOk));

        // download
        let resp = handle(Message::Download(Download {
            session_token: token,
            file_id,
        }), &store).await;
        assert!(matches!(resp, Message::DownloadResponse(_)));
    }

    #[tokio::test]
    async fn test_unauthorized_upload_fails() {
        let store = Store::new();
        let resp = handle(Message::Upload(Upload {
            session_token: vec![0u8; 32], // fake token
            file_id: vec![1u8; 32],
            ciphertext: vec![],
            encrypted_metadata: vec![],
            version: 1,
            signature: vec![0u8; 64],
        }), &store).await;
        assert!(matches!(resp, Message::Error(_)));
    }
}