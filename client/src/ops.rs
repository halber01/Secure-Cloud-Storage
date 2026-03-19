use std::path::Path;
use ed25519_dalek::{SigningKey, Signer};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use rustls::pki_types::ServerName;
use shared::frame::{send_frame, recv_frame};
use shared::messages::*;
use shared::crypto::*;
use shared::constants::*;

// TLS connection

/// Establishes a TLS connection to the server.
/// Uses a custom verifier that accepts self-signed certificates.
pub async fn connect(addr: &str) -> Result<TlsStream<TcpStream>, String> {
    // For development: accept self-signed certificates
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(tls_config));
    let stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("TCP connect failed: {e}"))?;

    let server_name = ServerName::try_from("localhost")
        .map_err(|e| format!("Invalid server name: {e}"))?;

    connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("TLS handshake failed: {e}"))
}

/// Certificate verifier that accepts any certificate.
/// ONLY for development: in production pin the server certificate.
use std::sync::Arc;
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use rustls::DigitallySignedStruct;

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
        &self, _msg: &[u8], _cert: &rustls::pki_types::CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self, _msg: &[u8], _cert: &rustls::pki_types::CertificateDer,
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

// Send/Receive helpers

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
    let (_, payload) = recv_frame(stream)
        .await
        .map_err(|e| e.to_string())?;
    let (msg, _): (Message, usize) = bincode::serde::decode_from_slice(
        &payload,
        bincode::config::standard(),
    ).map_err(|e| e.to_string())?;
    Ok(msg)
}

// Session state

pub struct Session {
    pub username: String,
    pub session_token: Vec<u8>,
    pub enc_key: [u8; 32],
    pub mac_key: [u8; 32],
    pub meta_key: [u8; 32],
    pub signing_key: SigningKey,
}

// Register

/// Derives keys from password and registers with the server.
/// The server only receives: username, salt, public_key.
pub async fn register<S>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Derive master key from password
    let salt = generate_salt();
    let master_key = derive_master_key(password, &salt)?;

    // Derive signing key from master key
    let signing_seed = derive_subkey(&master_key, HKDF_SIGN_LABEL);
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let public_key = signing_key.verifying_key().to_bytes().to_vec();

    send_msg(stream, Message::Register(Register {
        username: username.to_string(),
        salt: salt.to_vec(),
        public_key,
    })).await?;

    match recv_msg(stream).await? {
        Message::RegisterOk => Ok(()),
        Message::Error(e) => Err(e.message),
        _ => Err("Unexpected response".to_string()),
    }
}

// Login

/// Performs challenge-response login, returns a Session with derived keys.
pub async fn login<S>(
    stream: &mut S,
    username: &str,
    password: &str,
) -> Result<Session, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Step 1: request challenge
    send_msg(stream, Message::RequestChallenge(RequestChallenge {
        username: username.to_string(),
    })).await?;

    let (nonce, salt) = match recv_msg(stream).await? {
        Message::Challenge(c) => (c.nonce, c.salt),
        Message::Error(e) => return Err(e.message),
        _ => return Err("Unexpected response".to_string()),
    };

    // Step 2: re-derive master key from password + server salt
    let master_key = derive_master_key(password, &salt)?;

    // Derive all subkeys
    let enc_key  = derive_subkey(&master_key, HKDF_ENC_LABEL);
    let mac_key  = derive_subkey(&master_key, HKDF_MAC_LABEL);
    let meta_key = derive_subkey(&master_key, HKDF_META_LABEL);

    // Derive signing key — same seed as registration
    let signing_seed = derive_subkey(&master_key, HKDF_SIGN_LABEL);
    let signing_key = SigningKey::from_bytes(&signing_seed);

    // Sign "login:" || nonce
    let mut msg = b"login:".to_vec();
    msg.extend_from_slice(&nonce);
    let signature = signing_key.sign(&msg).to_bytes().to_vec();

    // Step 3: send login
    send_msg(stream, Message::Login(Login {
        username: username.to_string(),
        signature,
    })).await?;

    let session_token = match recv_msg(stream).await? {
        Message::LoginOk(l) => l.session_token,
        Message::Error(e) => return Err(e.message),
        _ => return Err("Unexpected response".to_string()),
    };

    Ok(Session {
        username: username.to_string(),
        session_token,
        enc_key,
        mac_key,
        meta_key,
        signing_key,
    })
}

// Upload

/// Reads a file, encrypts it, signs it, sends it to the server.
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
    // Read plaintext
    let plaintext = std::fs::read(local_path)
        .map_err(|e| e.to_string())?;

    if plaintext.len() > MAX_FRAME_SIZE - 1000 {
        return Err("File too large — maximum 16MB in v1".to_string());
    }

    // Compute file_id = HMAC(mac_key, filename) — hides filename from server
    let file_id = compute_file_id(&session.mac_key, remote_name);

    // Derive per-file key and encrypt content
    let file_key = derive_subkey(&session.enc_key, &file_id);
    let ciphertext = encrypt(&file_key, &plaintext)?;

    // Encrypt metadata — filename stays hidden from server
    let metadata = format!("{}:{}", remote_name, version);
    let encrypted_metadata = encrypt(&session.meta_key, metadata.as_bytes())?;

    // Sign file_id || version || ciphertext
    let mut sign_msg = Vec::new();
    sign_msg.extend_from_slice(&file_id);
    sign_msg.extend_from_slice(&version.to_le_bytes());
    sign_msg.extend_from_slice(&ciphertext);
    let signature = session.signing_key.sign(&sign_msg).to_bytes().to_vec();

    send_msg(stream, Message::Upload(Upload {
        session_token: session.session_token.clone(),
        file_id,
        ciphertext,
        encrypted_metadata,
        version,
        signature,
    })).await?;

    match recv_msg(stream).await? {
        Message::UploadOk => Ok(()),
        Message::Error(e) => Err(e.message),
        _ => Err("Unexpected response".to_string()),
    }
}

// Download

/// Downloads a file, verifies signature, decrypts, saves to disk.
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

    send_msg(stream, Message::Download(Download {
        session_token: session.session_token.clone(),
        file_id: file_id.clone(),
    })).await?;

    let resp = match recv_msg(stream).await? {
        Message::DownloadResponse(r) => r,
        Message::Error(e) => return Err(e.message),
        _ => return Err("Unexpected response".to_string()),
    };

    // Verify signature — proves server didn't tamper with the file
    let mut sign_msg = Vec::new();
    sign_msg.extend_from_slice(&file_id);
    sign_msg.extend_from_slice(&resp.version.to_le_bytes());
    sign_msg.extend_from_slice(&resp.ciphertext);
    let public_key = session.signing_key.verifying_key();
    let sig_bytes: [u8; 64] = resp.signature.try_into()
        .map_err(|_| "Invalid signature length".to_string())?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    use ed25519_dalek::Verifier;
    public_key.verify(&sign_msg, &sig)
        .map_err(|_| "Signature verification failed — file may be tampered".to_string())?;

    // Decrypt
    let file_key = derive_subkey(&session.enc_key, &file_id);
    let plaintext = decrypt(&file_key, &resp.ciphertext)?;

    // Save to disk
    std::fs::write(local_path, &plaintext)
        .map_err(|e| e.to_string())?;

    Ok(())
}

// List

/// Lists all files, decrypting metadata client-side.
pub async fn list<S>(
    stream: &mut S,
    session: &Session,
) -> Result<Vec<(String, u64)>, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    send_msg(stream, Message::List(List {
        session_token: session.session_token.clone(),
    })).await?;

    let entries = match recv_msg(stream).await? {
        Message::ListResponse(r) => r.list,
        Message::Error(e) => return Err(e.message),
        _ => return Err("Unexpected response".to_string()),
    };

    // Decrypt metadata for each entry client-side
    let mut files = Vec::new();
    for entry in entries {
        match decrypt(&session.meta_key, &entry.encrypted_metadata) {
            Ok(bytes) => {
                let meta = String::from_utf8_lossy(&bytes).to_string();
                // metadata format: "filename:version"
                let name = meta.split(':').next()
                    .unwrap_or("unknown")
                    .to_string();
                files.push((name, entry.version));
            }
            Err(_) => files.push(("<undecryptable>".to_string(), entry.version)),
        }
    }

    Ok(files)
}