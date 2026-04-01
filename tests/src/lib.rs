#[cfg(test)]
mod tests {
    use client::ops::{delete_file, download, get_version, list, login, register, upload};
    use server::handlers;
    use server::store::Store;
    use shared::frame::{recv_frame, send_frame};
    use shared::messages::*;
    use std::sync::Arc;
    use tokio::io::duplex;

    /// Simulates a server responding to one message
    async fn server_respond(
        server: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
        store: &Store,
    ) {
        let (_, payload) = recv_frame(server).await.unwrap();
        let (msg, _): (Message, usize) =
            bincode::serde::decode_from_slice(&payload, bincode::config::standard()).unwrap();
        let response = handlers::handle(msg, store).await;
        let type_byte = response.type_byte();
        let resp_payload =
            bincode::serde::encode_to_vec(&response, bincode::config::standard()).unwrap();
        send_frame(server, type_byte, &resp_payload).await.unwrap();
    }

    async fn try_server_respond(
        server: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
        store: &Store,
    ) -> Result<(), String> {
        let (_, payload) = recv_frame(server).await.map_err(|e| e.to_string())?;
        let (msg, _): (Message, usize) =
            bincode::serde::decode_from_slice(&payload, bincode::config::standard())
                .map_err(|e| e.to_string())?;
        let response = handlers::handle(msg, store).await;
        let type_byte = response.type_byte();
        let resp_payload = bincode::serde::encode_to_vec(&response, bincode::config::standard())
            .map_err(|e| e.to_string())?;
        send_frame(server, type_byte, &resp_payload)
            .await
            .map_err(|e| e.to_string())
    }

    fn start_test_server(
        store: Arc<Store>,
    ) -> impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
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

        register(&mut client, "alice", "correctpassword")
            .await
            .unwrap();
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
        upload(&mut client, &session, &tmp, "test.txt")
            .await
            .unwrap();

        // login again for fresh session
        let (_client2, _server2) = duplex(65536);
        // reuse same store via re-login
        let session2 = login(&mut client, "alice", "password123").await.unwrap();

        // download
        let out = std::env::temp_dir().join("test_download.txt");
        download(&mut client, &session2, "test.txt", &out)
            .await
            .unwrap();

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
        upload(&mut client, &session, &tmp, "myfile.txt")
            .await
            .unwrap();

        let files = list(&mut client, &session).await.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "myfile.txt");

        std::fs::remove_file(&tmp).unwrap();
    }

    #[tokio::test]
    async fn test_delete_file() {
        let store = Arc::new(Store::new());
        let mut client = start_test_server(Arc::clone(&store));

        // register and login
        register(&mut client, "alice", "password123").await.unwrap();
        let session = login(&mut client, "alice", "password123").await.unwrap();

        // upload a file
        let tmp = std::env::temp_dir().join("test_delete.txt");
        std::fs::write(&tmp, b"delete me").unwrap();
        upload(&mut client, &session, &tmp, "delete_me.txt").await.unwrap();

        // delete it
        delete_file(&mut client, &session, "delete_me.txt").await.unwrap();

        // try to download → should fail
        let out = std::env::temp_dir().join("test_delete_out.txt");
        let result = download(&mut client, &session, "delete_me.txt", &out).await;
        assert!(result.is_err());

        std::fs::remove_file(&tmp).unwrap();
    }

    #[tokio::test]
    async fn test_get_version_new_file() {
        let store = Arc::new(Store::new());
        let mut client = start_test_server(Arc::clone(&store));

        register(&mut client, "alice", "password123").await.unwrap();
        let session = login(&mut client, "alice", "password123").await.unwrap();

        // file doesn't exist yet → version should be 0
        let version = get_version(&mut client, &session, "nonexistent.txt").await.unwrap();
        assert_eq!(version, 0);
    }

    #[tokio::test]
    async fn test_get_version_after_upload() {
        let store = Arc::new(Store::new());
        let mut client = start_test_server(Arc::clone(&store));

        register(&mut client, "alice", "password123").await.unwrap();
        let session = login(&mut client, "alice", "password123").await.unwrap();

        let tmp = std::env::temp_dir().join("test_version.txt");
        std::fs::write(&tmp, b"versioned content").unwrap();
        upload(&mut client, &session, &tmp, "versioned.txt").await.unwrap();

        // version should be 1 after first upload
        let version = get_version(&mut client, &session, "versioned.txt").await.unwrap();
        assert_eq!(version, 1);

        std::fs::remove_file(&tmp).unwrap();
    }

    #[tokio::test]
    async fn test_auto_version_increment() {
        let store = Arc::new(Store::new());
        let mut client = start_test_server(Arc::clone(&store));

        register(&mut client, "alice", "password123").await.unwrap();
        let session = login(&mut client, "alice", "password123").await.unwrap();

        // first upload
        let tmp = std::env::temp_dir().join("test_increment.txt");
        std::fs::write(&tmp, b"version 1").unwrap();
        upload(&mut client, &session, &tmp, "increment.txt").await.unwrap();

        // second upload — same remote name
        std::fs::write(&tmp, b"version 2").unwrap();
        upload(&mut client, &session, &tmp, "increment.txt").await.unwrap();

        // version should be 2
        let version = get_version(&mut client, &session, "increment.txt").await.unwrap();
        assert_eq!(version, 2);

        // download and verify latest content
        let out = std::env::temp_dir().join("test_increment_out.txt");
        download(&mut client, &session, "increment.txt", &out).await.unwrap();
        let contents = std::fs::read(&out).unwrap();
        assert_eq!(contents, b"version 2");

        std::fs::remove_file(&tmp).unwrap();
        std::fs::remove_file(&out).unwrap();
    }

    #[tokio::test]
    async fn test_list_after_delete() {
        let store = Arc::new(Store::new());
        let mut client = start_test_server(Arc::clone(&store));

        register(&mut client, "alice", "password123").await.unwrap();
        let session = login(&mut client, "alice", "password123").await.unwrap();

        // upload two files
        let tmp1 = std::env::temp_dir().join("list_delete_1.txt");
        let tmp2 = std::env::temp_dir().join("list_delete_2.txt");
        std::fs::write(&tmp1, b"file one").unwrap();
        std::fs::write(&tmp2, b"file two").unwrap();

        upload(&mut client, &session, &tmp1, "file1.txt").await.unwrap();
        upload(&mut client, &session, &tmp2, "file2.txt").await.unwrap();

        // delete one
        delete_file(&mut client, &session, "file1.txt").await.unwrap();

        // list should only show one file
        let files = list(&mut client, &session).await.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "file2.txt");

        std::fs::remove_file(&tmp1).unwrap();
        std::fs::remove_file(&tmp2).unwrap();
    }
}
