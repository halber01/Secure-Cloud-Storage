mod config;
mod handlers;
mod store;

use config::SERVER_CONFIG;
use opaque_ke::ServerSetup;
use opaque_ke::rand::rngs::OsRng;
use rustls::ServerConfig;
use shared::crypto::DefaultCipherSuite;
use shared::frame::{recv_frame, send_frame};
use shared::messages::Message;
use std::sync::Arc;
use store::Store;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const SERVER_SETUP_PATH: &str = "server_setup.bin";

/// Loads the OPAQUE ServerSetup from disk, or generates and persists a new one.
/// The ServerSetup contains the server's long-term OPRF seed and keypair.
/// Losing it invalidates all registered users' password files.
fn load_or_create_server_setup() -> ServerSetup<DefaultCipherSuite> {
    if let Ok(bytes) = std::fs::read(SERVER_SETUP_PATH) {
        match ServerSetup::<DefaultCipherSuite>::deserialize(&bytes) {
            Ok(setup) => {
                println!("Loaded ServerSetup from {SERVER_SETUP_PATH}");
                return setup;
            }
            Err(e) => eprintln!("Warning: failed to deserialize ServerSetup ({e}), generating new"),
        }
    }
    let setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);
    let bytes = setup.serialize();
    if let Err(e) = std::fs::write(SERVER_SETUP_PATH, &*bytes) {
        eprintln!("Warning: could not persist ServerSetup: {e}");
    } else {
        println!("Generated and saved new ServerSetup to {SERVER_SETUP_PATH}");
    }
    setup
}

#[tokio::main]
async fn main() {
    let server_setup = load_or_create_server_setup();
    let store = Store::new(server_setup);

    // TLS setup
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("Failed to generate certificate");

    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("Failed to build TLS config");

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(format!("{}:{}", SERVER_CONFIG.address, SERVER_CONFIG.port))
        .await
        .expect("Failed to bind");

    println!(
        "Server listening on {}:{}",
        SERVER_CONFIG.address, SERVER_CONFIG.port
    );

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Accept error: {e}");
                continue;
            }
        };

        let acceptor = acceptor.clone();
        let store = store.clone();

        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    println!("Client connected: {addr}");
                    handle_client(tls_stream, store).await;
                    println!("Client disconnected: {addr}");
                }
                Err(e) => eprintln!("TLS handshake failed: {e}"),
            }
        });
    }
}

async fn handle_client<S>(mut stream: S, store: Store)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let (_msg_type, payload) = match recv_frame(&mut stream).await {
            Ok(f) => f,
            Err(_) => break,
        };

        let (msg, _): (Message, usize) =
            match bincode::serde::decode_from_slice(&payload, bincode::config::standard()) {
                Ok(m) => m,
                Err(_) => {
                    let err = Message::Error(shared::messages::Error {
                        code: 0x07,
                        message: "Malformed frame".to_string(),
                    });
                    let _ = send_message(&mut stream, err).await;
                    continue;
                }
            };

        let response = handlers::handle(msg, &store).await;

        if send_message(&mut stream, response).await.is_err() {
            break;
        }
    }
}

async fn send_message<S>(stream: &mut S, msg: Message) -> Result<(), std::io::Error>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let type_byte = msg.type_byte();
    let payload = bincode::serde::encode_to_vec(&msg, bincode::config::standard())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    send_frame(stream, type_byte, &payload).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_send_and_receive_message() {
        let (mut client, mut server) = duplex(1024);

        let msg = Message::RegisterOk;
        send_message(&mut client, msg).await.unwrap();

        let (_, payload) = recv_frame(&mut server).await.unwrap();
        let (decoded, _): (Message, usize) =
            bincode::serde::decode_from_slice(&payload, bincode::config::standard()).unwrap();

        assert!(matches!(decoded, Message::RegisterOk));
    }

    #[tokio::test]
    async fn test_malformed_payload_returns_error() {
        let (mut client, mut server) = duplex(1024);

        send_frame(&mut client, 0x01, b"not valid bincode")
            .await
            .unwrap();

        let (_, payload) = recv_frame(&mut server).await.unwrap();
        let result: Result<(Message, usize), _> =
            bincode::serde::decode_from_slice(&payload, bincode::config::standard());

        assert!(result.is_err());
    }
}
