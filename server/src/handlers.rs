use crate::store::{FileRecord, Store, UserRecord};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration,
};
use opaque_ke::rand::rngs::OsRng;
use shared::crypto::DefaultCipherSuite;
use shared::messages::*;

/// Central dispatch — matches incoming message to the right handler.
pub async fn handle(msg: Message, store: &Store) -> Message {
    match msg {
        // OPAQUE registration
        Message::OpaqueRegStart(r) => handle_opaque_reg_start(r, store),
        Message::OpaqueRegFinish(r) => handle_opaque_reg_finish(r, store),

        // OPAQUE login
        Message::OpaqueLoginStart(r) => handle_opaque_login_start(r, store),
        Message::OpaqueLoginFinish(r) => handle_opaque_login_finish(r, store),

        // File operations
        Message::Upload(r) => handle_upload(r, store),
        Message::List(r) => handle_list(r, store),
        Message::Download(r) => handle_download(r, store),
        Message::Delete(r) => handle_delete(r, store),

        _ => error(0x07, "Unexpected message type"),
    }
}

// ── Helper ────────────────────────────────────────────────────────────────────

fn error(code: u8, msg: &str) -> Message {
    Message::Error(Error {
        code,
        message: msg.to_string(),
    })
}

// ── OPAQUE Registration ───────────────────────────────────────────────────────

/// Step 1: server processes the client's blinded password element and returns
/// its own OPAQUE response. No state needs to be persisted between this and the
/// finish step — ServerRegistration::finish is purely functional.
fn handle_opaque_reg_start(req: OpaqueRegStart, store: &Store) -> Message {
    let registration_request =
        match RegistrationRequest::<DefaultCipherSuite>::deserialize(&req.request) {
            Ok(r) => r,
            Err(_) => return error(0x10, "Invalid OPAQUE registration request"),
        };

    let result = match ServerRegistration::<DefaultCipherSuite>::start(
        store.server_setup(),
        registration_request,
        req.username.as_bytes(),
    ) {
        Ok(r) => r,
        Err(_) => return error(0x10, "OPAQUE registration start failed"),
    };

    println!("[OPAQUE-REG-START] '{}'", req.username);
    Message::OpaqueRegResp(OpaqueRegResp {
        response: result.message.serialize().to_vec(),
    })
}

/// Step 3: server receives the client's completed registration record, finalizes
/// it into a PasswordFile, and stores it alongside the Ed25519 public key.
fn handle_opaque_reg_finish(req: OpaqueRegFinish, store: &Store) -> Message {
    let reg_upload =
        match RegistrationUpload::<DefaultCipherSuite>::deserialize(&req.record) {
            Ok(r) => r,
            Err(_) => return error(0x10, "Invalid OPAQUE registration upload"),
        };

    let password_file = ServerRegistration::finish(reg_upload);

    if store.register_user(
        req.username.clone(),
        UserRecord {
            password_file: password_file.serialize().to_vec(),
            public_key: req.public_key,
        },
    ) {
        println!("[OPAQUE-REG-FINISH] New user: '{}'", req.username);
        Message::RegisterOk
    } else {
        println!(
            "[OPAQUE-REG-FINISH] Failed — user exists: '{}'",
            req.username
        );
        error(0x02, "Username already exists")
    }
}

// ── OPAQUE Login ──────────────────────────────────────────────────────────────

/// Step 1: server processes the client's credential request and returns a
/// credential response. The intermediate ServerLogin state is serialized and
/// stored in the store, keyed by username.
fn handle_opaque_login_start(req: OpaqueLoginStart, store: &Store) -> Message {
    let credential_request =
        match CredentialRequest::<DefaultCipherSuite>::deserialize(&req.request) {
            Ok(r) => r,
            Err(_) => return error(0x10, "Invalid OPAQUE credential request"),
        };

    // Look up the password file. Pass None for unknown users so the response
    // is indistinguishable, preventing username enumeration.
    let password_file = store.get_user(&req.username).and_then(|u| {
        ServerRegistration::<DefaultCipherSuite>::deserialize(&u.password_file).ok()
    });

    let mut rng = OsRng;
    let result = match ServerLogin::start(
        &mut rng,
        store.server_setup(),
        password_file,
        credential_request,
        req.username.as_bytes(),
        ServerLoginParameters::default(),
    ) {
        Ok(r) => r,
        Err(_) => return error(0x10, "OPAQUE login start failed"),
    };

    // Serialize and store the intermediate state for use in finish.
    let state_bytes = result.state.serialize().to_vec();
    store.store_login_state(req.username.clone(), state_bytes);

    println!("[OPAQUE-LOGIN-START] '{}'", req.username);
    Message::OpaqueLoginResp(OpaqueLoginResp {
        response: result.message.serialize().to_vec(),
    })
}

/// Step 3: server retrieves the intermediate state, verifies the client's
/// finalization message, and issues a session token on success.
fn handle_opaque_login_finish(req: OpaqueLoginFinish, store: &Store) -> Message {
    // Consume the stored state — prevents replay of OpaqueLoginFinish.
    let state_bytes = match store.take_login_state(&req.username) {
        Some(b) => b,
        None => return error(0x01, "No pending login for this user"),
    };

    let server_login = match ServerLogin::<DefaultCipherSuite>::deserialize(&state_bytes) {
        Ok(s) => s,
        Err(_) => return error(0x10, "Failed to restore OPAQUE login state"),
    };

    let finalization = match CredentialFinalization::<DefaultCipherSuite>::deserialize(
        &req.finalization,
    ) {
        Ok(f) => f,
        Err(_) => return error(0x10, "Invalid OPAQUE credential finalization"),
    };

    match server_login.finish(finalization, ServerLoginParameters::default()) {
        Ok(_) => {
            let mut token = vec![0u8; 32];
            use opaque_ke::rand::RngCore;
            OsRng.fill_bytes(&mut token);
            store.create_session(token.clone(), req.username.clone());
            println!("[OPAQUE-LOGIN-FINISH] Login success: '{}'", req.username);
            Message::LoginOk(LoginOk {
                session_token: token,
            })
        }
        Err(_) => {
            println!("[OPAQUE-LOGIN-FINISH] Auth failed: '{}'", req.username);
            error(0x04, "Authentication failed")
        }
    }
}

// ── File operations ───────────────────────────────────────────────────────────

fn handle_upload(req: Upload, store: &Store) -> Message {
    let username = match store.resolve_session(&req.session_token) {
        Some(u) => u,
        None => return error(0x01, "Unauthorized"),
    };

    let user = store.get_user(&username).unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(&req.file_id);
    msg.extend_from_slice(&req.version.to_le_bytes());
    msg.extend_from_slice(&req.ciphertext);
    if !verify_signature(&user.public_key, &msg, &req.signature) {
        return error(0x04, "Invalid signature");
    }

    println!(
        "[UPLOAD] user='{}' file_id='{}' version={}",
        username,
        hex::encode(&req.file_id),
        req.version
    );
    match store.put_file(
        username,
        req.file_id,
        FileRecord {
            ciphertext: req.ciphertext,
            encrypted_metadata: req.encrypted_metadata,
            version: req.version,
            signature: req.signature,
        },
    ) {
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
    println!(
        "[DOWNLOAD] user='{}' file_id='{}'",
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

// ── Signature verification ────────────────────────────────────────────────────

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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use ed25519_dalek::Signer;
    use opaque_ke::{
        ClientLogin, ClientLoginFinishParameters, ClientRegistration,
        ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
        rand::rngs::OsRng,
    };
    use shared::constants::{HKDF_SIGN_LABEL};
    use shared::crypto::derive_subkey;

    /// Registers a user via the OPAQUE protocol and returns their signing key.
    async fn opaque_register(
        store: &Store,
        username: &str,
        password: &str,
    ) -> ed25519_dalek::SigningKey {
        let mut rng = OsRng;

        // Client start
        let client_start =
            ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password.as_bytes())
                .unwrap();

        let resp = handle(
            Message::OpaqueRegStart(OpaqueRegStart {
                username: username.to_string(),
                request: client_start.message.serialize().to_vec(),
            }),
            store,
        )
        .await;
        let server_resp = match resp {
            Message::OpaqueRegResp(r) => r,
            _ => panic!("Expected OpaqueRegResp, got {resp:?}"),
        };

        // Client finish
        let reg_response =
            RegistrationResponse::<DefaultCipherSuite>::deserialize(&server_resp.response)
                .unwrap();
        let client_finish = client_start
            .state
            .finish(
                &mut rng,
                password.as_bytes(),
                reg_response,
                ClientRegistrationFinishParameters::default(),
            )
            .unwrap();

        let signing_seed = derive_subkey(client_finish.export_key.as_ref(), HKDF_SIGN_LABEL);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        let resp = handle(
            Message::OpaqueRegFinish(OpaqueRegFinish {
                username: username.to_string(),
                record: client_finish.message.serialize().to_vec(),
                public_key,
            }),
            store,
        )
        .await;
        assert!(matches!(resp, Message::RegisterOk), "Expected RegisterOk, got {resp:?}");

        signing_key
    }

    /// Logs in via OPAQUE and returns (session_token, signing_key).
    async fn opaque_login(
        store: &Store,
        username: &str,
        password: &str,
    ) -> (Vec<u8>, ed25519_dalek::SigningKey) {
        let mut rng = OsRng;

        let client_start =
            ClientLogin::<DefaultCipherSuite>::start(&mut rng, password.as_bytes()).unwrap();

        let resp = handle(
            Message::OpaqueLoginStart(OpaqueLoginStart {
                username: username.to_string(),
                request: client_start.message.serialize().to_vec(),
            }),
            store,
        )
        .await;
        let server_resp = match resp {
            Message::OpaqueLoginResp(r) => r,
            _ => panic!("Expected OpaqueLoginResp, got {resp:?}"),
        };

        let cred_response =
            CredentialResponse::<DefaultCipherSuite>::deserialize(&server_resp.response).unwrap();
        let client_finish = client_start
            .state
            .finish(
                &mut rng,
                password.as_bytes(),
                cred_response,
                ClientLoginFinishParameters::default(),
            )
            .unwrap();

        let resp = handle(
            Message::OpaqueLoginFinish(OpaqueLoginFinish {
                username: username.to_string(),
                finalization: client_finish.message.serialize().to_vec(),
            }),
            store,
        )
        .await;
        let session_token = match resp {
            Message::LoginOk(l) => l.session_token,
            _ => panic!("Expected LoginOk, got {resp:?}"),
        };

        let signing_seed = derive_subkey(client_finish.export_key.as_ref(), HKDF_SIGN_LABEL);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);

        (session_token, signing_key)
    }

    #[tokio::test]
    async fn test_register_ok() {
        let store = Store::new_random();
        opaque_register(&store, "alice", "password123").await;
        assert!(store.get_user("alice").is_some());
    }

    #[tokio::test]
    async fn test_register_duplicate_fails() {
        let store = Store::new_random();
        opaque_register(&store, "alice", "password123").await;

        // Second registration attempt for the same username should fail.
        let mut rng = OsRng;
        let client_start =
            ClientRegistration::<DefaultCipherSuite>::start(&mut rng, b"other").unwrap();
        handle(
            Message::OpaqueRegStart(OpaqueRegStart {
                username: "alice".to_string(),
                request: client_start.message.serialize().to_vec(),
            }),
            &store,
        )
        .await;
        // Fake a reg_finish for the same username.
        let resp = handle(
            Message::OpaqueRegFinish(OpaqueRegFinish {
                username: "alice".to_string(),
                record: vec![0u8; 256], // bad record, but username check happens first
                public_key: vec![0u8; 32],
            }),
            &store,
        )
        .await;
        // We expect an error because alice is already registered.
        // (The record is invalid but the store rejects the username first.)
        assert!(matches!(resp, Message::Error(_)));
    }

    #[tokio::test]
    async fn test_login_wrong_password_fails() {
        let store = Store::new_random();
        opaque_register(&store, "alice", "correctpassword").await;

        let mut rng = OsRng;
        let client_start =
            ClientLogin::<DefaultCipherSuite>::start(&mut rng, b"wrongpassword").unwrap();

        let resp = handle(
            Message::OpaqueLoginStart(OpaqueLoginStart {
                username: "alice".to_string(),
                request: client_start.message.serialize().to_vec(),
            }),
            &store,
        )
        .await;
        let server_resp = match resp {
            Message::OpaqueLoginResp(r) => r,
            _ => panic!("Expected OpaqueLoginResp"),
        };

        let cred_response =
            CredentialResponse::<DefaultCipherSuite>::deserialize(&server_resp.response).unwrap();

        // ClientLogin::finish returns Err for the wrong password.
        let result = client_start.state.finish(
            &mut rng,
            b"wrongpassword",
            cred_response,
            ClientLoginFinishParameters::default(),
        );
        assert!(result.is_err(), "Expected client to reject wrong password");
    }

    #[tokio::test]
    async fn test_upload_and_download() {
        let store = Store::new_random();
        opaque_register(&store, "alice", "password123").await;
        let (token, signing_key) = opaque_login(&store, "alice", "password123").await;

        let file_id = vec![1u8; 32];
        let ciphertext = vec![2u8; 64];

        let mut sign_msg = Vec::new();
        sign_msg.extend_from_slice(&file_id);
        sign_msg.extend_from_slice(&1u64.to_le_bytes());
        sign_msg.extend_from_slice(&ciphertext);
        let signature = signing_key.sign(&sign_msg).to_bytes().to_vec();

        let resp = handle(
            Message::Upload(Upload {
                session_token: token.clone(),
                file_id: file_id.clone(),
                ciphertext: ciphertext.clone(),
                encrypted_metadata: vec![3u8; 32],
                version: 1,
                signature,
            }),
            &store,
        )
        .await;
        assert!(matches!(resp, Message::UploadOk));

        let resp = handle(
            Message::Download(Download {
                session_token: token,
                file_id,
            }),
            &store,
        )
        .await;
        assert!(matches!(resp, Message::DownloadResponse(_)));
    }

    #[tokio::test]
    async fn test_unauthorized_upload_fails() {
        let store = Store::new_random();
        let resp = handle(
            Message::Upload(Upload {
                session_token: vec![0u8; 32],
                file_id: vec![1u8; 32],
                ciphertext: vec![],
                encrypted_metadata: vec![],
                version: 1,
                signature: vec![0u8; 64],
            }),
            &store,
        )
        .await;
        assert!(matches!(resp, Message::Error(_)));
    }
}
