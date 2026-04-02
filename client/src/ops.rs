use ed25519_dalek::{Signer, SigningKey};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use opaque_ke::rand::rngs::OsRng;
use rustls::pki_types::ServerName;
use shared::constants::*;
use shared::crypto::{DefaultCipherSuite, compute_file_id, decrypt, derive_subkey, encrypt};
use shared::frame::{recv_frame, send_frame};
use shared::messages::*;
use std::path::Path;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

// ── TLS connection ────────────────────────────────────────────────────────────

/// Establishes a TLS connection to the server.
/// Uses a custom verifier that accepts self-signed certificates.
pub async fn connect(addr: &str) -> Result<TlsStream<TcpStream>, String> {
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(tls_config));
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("TCP connect failed: {e}"))?;

    let server_name =
        ServerName::try_from("localhost").map_err(|e| format!("Invalid server name: {e}"))?;

    connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("TLS handshake failed: {e}"))
}

use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use std::sync::Arc;

#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &ServerName,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _msg: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _msg: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

// ── Send / Receive helpers ────────────────────────────────────────────────────

async fn send_msg<S>(stream: &mut S, msg: Message) -> Result<(), String>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let type_byte = msg.type_byte();
    let payload = bincode::serde::encode_to_vec(&msg, bincode::config::standard())
        .map_err(|e| e.to_string())?;
    send_frame(stream, type_byte, &payload)
        .await
        .map_err(|e| e.to_string())
}

async fn recv_msg<S>(stream: &mut S) -> Result<Message, String>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let (_, payload) = recv_frame(stream).await.map_err(|e| e.to_string())?;
    let (msg, _): (Message, usize) =
        bincode::serde::decode_from_slice(&payload, bincode::config::standard())
            .map_err(|e| e.to_string())?;
    Ok(msg)
}

// ── Session state ─────────────────────────────────────────────────────────────

pub struct Session {
    pub username: String,
    pub session_token: Vec<u8>,
    pub enc_key: [u8; 32],
    pub mac_key: [u8; 32],
    pub meta_key: [u8; 32],
    pub signing_key: SigningKey,
}

// ── OPAQUE Registration ───────────────────────────────────────────────────────

/// Registers with the server using the OPAQUE protocol (2 round trips).
///
/// The password never leaves the client — only a blinded element and the
/// final encrypted envelope are sent. The Ed25519 public key derived from
/// `export_key` is also sent so the server can verify future file signatures.
pub async fn register<S>(stream: &mut S, username: &str, password: &str) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut rng = OsRng;

    // Step 1: client blinds the password and sends RegistrationRequest.
    let client_start =
        ClientRegistration::<DefaultCipherSuite>::start(&mut rng, password.as_bytes())
            .map_err(|e| format!("OPAQUE reg start: {e}"))?;

    send_msg(
        stream,
        Message::OpaqueRegStart(OpaqueRegStart {
            username: username.to_string(),
            request: client_start.message.serialize().to_vec(),
        }),
    )
    .await?;

    // Step 2: receive RegistrationResponse from server.
    let server_resp = match recv_msg(stream).await? {
        Message::OpaqueRegResp(r) => r,
        Message::Error(e) => return Err(e.message),
        _ => return Err("Unexpected response to OpaqueRegStart".to_string()),
    };

    let reg_response =
        RegistrationResponse::<DefaultCipherSuite>::deserialize(&server_resp.response)
            .map_err(|e| format!("OPAQUE reg response deserialize: {e}"))?;

    // Step 3: finalize on the client side and derive the signing key from export_key.
    let client_finish = client_start
        .state
        .finish(
            &mut rng,
            password.as_bytes(),
            reg_response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|e| format!("OPAQUE reg finish: {e}"))?;

    // Derive Ed25519 signing key from export_key (same derivation used at login).
    let signing_seed = derive_subkey(client_finish.export_key.as_ref(), HKDF_SIGN_LABEL);
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let public_key = signing_key.verifying_key().to_bytes().to_vec();

    // Step 4: send RegistrationUpload + public key; receive acknowledgement.
    send_msg(
        stream,
        Message::OpaqueRegFinish(OpaqueRegFinish {
            username: username.to_string(),
            record: client_finish.message.serialize().to_vec(),
            public_key,
        }),
    )
    .await?;

    match recv_msg(stream).await? {
        Message::RegisterOk => Ok(()),
        Message::Error(e) => Err(e.message),
        _ => Err("Unexpected response to OpaqueRegFinish".to_string()),
    }
}

// ── OPAQUE Login ──────────────────────────────────────────────────────────────

/// Logs in using the OPAQUE protocol (2 round trips).
///
/// On success the `export_key` from OPAQUE replaces the old Argon2id
/// `master_key`. All HKDF subkey derivation is unchanged.
/// Wrong-password detection happens locally — the server never learns
/// whether the attempt failed.
pub async fn login<S>(stream: &mut S, username: &str, password: &str) -> Result<Session, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut rng = OsRng;

    // Step 1: client sends CredentialRequest.
    let client_start =
        ClientLogin::<DefaultCipherSuite>::start(&mut rng, password.as_bytes())
            .map_err(|e| format!("OPAQUE login start: {e}"))?;

    send_msg(
        stream,
        Message::OpaqueLoginStart(OpaqueLoginStart {
            username: username.to_string(),
            request: client_start.message.serialize().to_vec(),
        }),
    )
    .await?;

    // Step 2: receive CredentialResponse from server.
    let server_resp = match recv_msg(stream).await? {
        Message::OpaqueLoginResp(r) => r,
        Message::Error(e) => return Err(e.message),
        _ => return Err("Unexpected response to OpaqueLoginStart".to_string()),
    };

    let cred_response =
        CredentialResponse::<DefaultCipherSuite>::deserialize(&server_resp.response)
            .map_err(|e| format!("OPAQUE cred response deserialize: {e}"))?;

    // Step 3: finalize locally. Returns Err immediately if the password is wrong —
    // no network round trip needed to detect a bad password.
    let client_finish = client_start
        .state
        .finish(
            &mut rng,
            password.as_bytes(),
            cred_response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| "Invalid password".to_string())?;

    // Step 4: send CredentialFinalization; receive session token.
    send_msg(
        stream,
        Message::OpaqueLoginFinish(OpaqueLoginFinish {
            username: username.to_string(),
            finalization: client_finish.message.serialize().to_vec(),
        }),
    )
    .await?;

    let session_token = match recv_msg(stream).await? {
        Message::LoginOk(l) => l.session_token,
        Message::Error(e) => return Err(e.message),
        _ => return Err("Unexpected response to OpaqueLoginFinish".to_string()),
    };

    // Derive all subkeys from export_key (replaces the old Argon2id master_key).
    let export_key = client_finish.export_key;
    let enc_key = derive_subkey(export_key.as_ref(), HKDF_ENC_LABEL);
    let mac_key = derive_subkey(export_key.as_ref(), HKDF_MAC_LABEL);
    let meta_key = derive_subkey(export_key.as_ref(), HKDF_META_LABEL);
    let signing_seed = derive_subkey(export_key.as_ref(), HKDF_SIGN_LABEL);
    let signing_key = SigningKey::from_bytes(&signing_seed);

    Ok(Session {
        username: username.to_string(),
        session_token,
        enc_key,
        mac_key,
        meta_key,
        signing_key,
    })
}

// ── Upload ────────────────────────────────────────────────────────────────────

/// Reads a file, encrypts it, signs it, and sends it to the server.
pub async fn upload<S>(
    stream: &mut S,
    session: &Session,
    local_path: &Path,
    remote_name: &str,
    version: u64,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let plaintext = std::fs::read(local_path).map_err(|e| e.to_string())?;

    if plaintext.len() > MAX_FRAME_SIZE - 1000 {
        return Err("File too large — maximum 16MB in v1".to_string());
    }

    let file_id = compute_file_id(&session.mac_key, remote_name);
    let file_key = derive_subkey(&session.enc_key, &file_id);
    let ciphertext = encrypt(&file_key, &plaintext)?;

    let metadata = format!("{}:{}", remote_name, version);
    let encrypted_metadata = encrypt(&session.meta_key, metadata.as_bytes())?;

    let mut sign_msg = Vec::new();
    sign_msg.extend_from_slice(&file_id);
    sign_msg.extend_from_slice(&version.to_le_bytes());
    sign_msg.extend_from_slice(&ciphertext);
    let signature = session.signing_key.sign(&sign_msg).to_bytes().to_vec();

    send_msg(
        stream,
        Message::Upload(Upload {
            session_token: session.session_token.clone(),
            file_id,
            ciphertext,
            encrypted_metadata,
            version,
            signature,
        }),
    )
    .await?;

    match recv_msg(stream).await? {
        Message::UploadOk => Ok(()),
        Message::Error(e) => Err(e.message),
        _ => Err("Unexpected response".to_string()),
    }
}

// ── Download ──────────────────────────────────────────────────────────────────

/// Downloads a file, verifies its signature, decrypts it, and saves it to disk.
pub async fn download<S>(
    stream: &mut S,
    session: &Session,
    remote_name: &str,
    local_path: &Path,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let file_id = compute_file_id(&session.mac_key, remote_name);

    send_msg(
        stream,
        Message::Download(Download {
            session_token: session.session_token.clone(),
            file_id: file_id.clone(),
        }),
    )
    .await?;

    let resp = match recv_msg(stream).await? {
        Message::DownloadResponse(r) => r,
        Message::Error(e) => return Err(e.message),
        _ => return Err("Unexpected response".to_string()),
    };

    // Verify signature — proves the server didn't tamper with the file.
    let mut sign_msg = Vec::new();
    sign_msg.extend_from_slice(&file_id);
    sign_msg.extend_from_slice(&resp.version.to_le_bytes());
    sign_msg.extend_from_slice(&resp.ciphertext);
    let public_key = session.signing_key.verifying_key();
    let sig_bytes: [u8; 64] = resp
        .signature
        .try_into()
        .map_err(|_| "Invalid signature length".to_string())?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    use ed25519_dalek::Verifier;
    public_key
        .verify(&sign_msg, &sig)
        .map_err(|_| "Signature verification failed — file may be tampered".to_string())?;

    let file_key = derive_subkey(&session.enc_key, &file_id);
    let plaintext = decrypt(&file_key, &resp.ciphertext)?;
    std::fs::write(local_path, &plaintext).map_err(|e| e.to_string())?;

    Ok(())
}

// ── List ──────────────────────────────────────────────────────────────────────

/// Lists all files, decrypting metadata client-side.
pub async fn list<S>(stream: &mut S, session: &Session) -> Result<Vec<(String, u64)>, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    send_msg(
        stream,
        Message::List(List {
            session_token: session.session_token.clone(),
        }),
    )
    .await?;

    let entries = match recv_msg(stream).await? {
        Message::ListResponse(r) => r.list,
        Message::Error(e) => return Err(e.message),
        _ => return Err("Unexpected response".to_string()),
    };

    let mut files = Vec::new();
    for entry in entries {
        match decrypt(&session.meta_key, &entry.encrypted_metadata) {
            Ok(bytes) => {
                let meta = String::from_utf8_lossy(&bytes).to_string();
                let name = meta.split(':').next().unwrap_or("unknown").to_string();
                files.push((name, entry.version));
            }
            Err(_) => files.push(("<undecryptable>".to_string(), entry.version)),
        }
    }

    Ok(files)
}
