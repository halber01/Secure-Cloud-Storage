#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use shared::messages::*;
    use tokio::io::duplex;
    use client::ops::{download, list, login, register, upload};
    use server::handlers;
    use server::store::Store;
    use shared::frame::{recv_frame, send_frame};

    /// Simulates a server responding to one message
    async fn server_respond(server: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin), store: &Store) {
        let (_, payload) = recv_frame(server).await.unwrap();
        let (msg, _): (Message, usize) = bincode::serde::decode_from_slice(
            &payload,
            bincode::config::standard()
        ).unwrap();
        let response = handlers::handle(msg, store).await;
        let type_byte = response.type_byte();
        let resp_payload = bincode::serde::encode_to_vec(
            &response,
            bincode::config::standard()
        ).unwrap();
        send_frame(server, type_byte, &resp_payload).await.unwrap();
    }

    async fn try_server_respond(
        server: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
        store: &Store
    ) -> Result<(), String> {
        let (_, payload) = recv_frame(server).await.map_err(|e| e.to_string())?;
        let (msg, _): (Message, usize) = bincode::serde::decode_from_slice(
            &payload,
            bincode::config::standard()
        ).map_err(|e| e.to_string())?;
        let response = handlers::handle(msg, store).await;
        let type_byte = response.type_byte();
        let resp_payload = bincode::serde::encode_to_vec(
            &response,
            bincode::config::standard()
        ).map_err(|e| e.to_string())?;
        send_frame(server, type_byte, &resp_payload).await.map_err(|e| e.to_string())
    }

    fn start_test_server(store: Arc<Store>) -> impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
        let (client_end, mut server_end) = tokio::io::duplex(65536);
        tokio::spawn(async move {
            loop {
                match try_server_respond(&mut server_end, &store).await {
                    Ok(()) => continue,
                    Err(_) => break,
                }
            }
        });
        client_end
    }

    #[tokio::test]
    async fn test_register_login_roundtrip() {
        let store = Arc::new(Store::new());
        let mut client = start_test_server(Arc::clone(&store));

        register(&mut client, "alice", "password123").await.unwrap();
        let session = login(&mut client, "alice", "password123").await.unwrap();
        assert_eq!(session.username, "alice");
    }

    #[tokio::test]
    async fn test_wrong_password_fails() {
        let store = Arc::new(Store::new());
        let mut client = start_test_server(Arc::clone(&store));

        register(&mut client, "alice", "correctpassword").await.unwrap();
        let result = login(&mut client, "alice", "wrongpassword").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_upload_download_roundtrip() {
        let store = Arc::new(Store::new());
        let mut client = start_test_server(Arc::clone(&store));

        // register and login
        register(&mut client, "alice", "password123").await.unwrap();
        let session = login(&mut client, "alice", "password123").await.unwrap();

        // write a temp file
        let tmp = std::env::temp_dir().join("test_upload.txt");
        std::fs::write(&tmp, b"secret file contents").unwrap();

        // upload
        upload(&mut client, &session, &tmp, "test.txt").await.unwrap();

        // login again for fresh session
        let (_client2, _server2) = duplex(65536);
        // reuse same store via re-login
        let session2 = login(&mut client, "alice", "password123").await.unwrap();

        // download
        let out = std::env::temp_dir().join("test_download.txt");
        download(&mut client, &session2, "test.txt", &out).await.unwrap();

        // verify contents match
        let contents = std::fs::read(&out).unwrap();
        assert_eq!(contents, b"secret file contents");

        std::fs::remove_file(&tmp).unwrap();
        std::fs::remove_file(&out).unwrap();
    }

    #[tokio::test]
    async fn test_list_shows_decrypted_filenames() {
        let store = Arc::new(Store::new());
        let mut client = start_test_server(Arc::clone(&store));

        register(&mut client, "alice", "password123").await.unwrap();
        let session = login(&mut client, "alice", "password123").await.unwrap();

        let tmp = std::env::temp_dir().join("list_test.txt");
        std::fs::write(&tmp, b"data").unwrap();
        upload(&mut client, &session, &tmp, "myfile.txt").await.unwrap();

        let files = list(&mut client, &session).await.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "myfile.txt");

        std::fs::remove_file(&tmp).unwrap();
    }
}