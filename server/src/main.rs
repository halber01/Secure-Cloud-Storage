mod handlers;
mod store;
mod config;

use std::sync::Arc;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use store::Store;
use shared::messages::Message;
use shared::frame::{send_frame, recv_frame};
use config::SERVER_CONFIG;

#[tokio::main]
async fn main() {
    let store = Store::new();

    // TLS setup
    let cert = rcgen::generate_simple_self_signed(
        vec!["localhost".to_string()]
    ).expect("Failed to generate certificate");

    let cert_der = rustls::pki_types::CertificateDer::from(
        cert.cert.der().to_vec()
    );
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        cert.key_pair.serialize_der().into()
    );

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("Failed to build TLS config");

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // TCP listener
    let listener = TcpListener::bind(format!("{}:{}", SERVER_CONFIG.address, SERVER_CONFIG.port))
        .await
        .expect("Failed to bind");

    println!("Server listening on {}:{}", SERVER_CONFIG.address, SERVER_CONFIG.port);

    // Accept loop
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => { eprintln!("Accept error: {e}"); continue; }
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

// Per-client handler
async fn handle_client<S>(mut stream: S, store: Store)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        // Read one frame
        let (_msg_type, payload) = match recv_frame(&mut stream).await {
            Ok(f) => f,
            Err(_) => break, // client disconnected
        };

        // Deserialize message
        let (msg, _): (Message, usize) = match bincode::serde::decode_from_slice(
            &payload,
            bincode::config::standard()
        ) {
            Ok(m) => m,
            Err(_) => {
                // Send error frame and continue
                let err = Message::Error(shared::messages::Error {
                    code: 0x07,
                    message: "Malformed frame".to_string(),
                });
                let _ = send_message(&mut stream, err).await;
                continue;
            }
        };

        // Dispatch to handler
        let response = handlers::handle(msg, &store).await;

        // Send response
        if send_message(&mut stream, response).await.is_err() {
            break;
        }
    }
}

// Send a Message as a frame

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

        // send a message on one end
        let msg = Message::RegisterOk;
        send_message(&mut client, msg).await.unwrap();

        // receive and deserialize on the other end
        let (_, payload) = recv_frame(&mut server).await.unwrap();
        let (decoded, _): (Message, usize) = bincode::serde::decode_from_slice(
            &payload,
            bincode::config::standard()
        ).unwrap();

        assert!(matches!(decoded, Message::RegisterOk));
    }

    #[tokio::test]
    async fn test_malformed_payload_returns_error() {
        let (mut client, mut server) = duplex(1024);

        // send garbage payload
        send_frame(&mut client, 0x01, b"not valid bincode").await.unwrap();

        let (_, payload) = recv_frame(&mut server).await.unwrap();
        let result: Result<(Message, usize), _> = bincode::serde::decode_from_slice(
            &payload,
            bincode::config::standard()
        );

        assert!(result.is_err());
    }
}