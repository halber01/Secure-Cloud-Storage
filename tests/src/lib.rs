#[cfg(test)]
mod tests {
    use client::ops::{download, list, login, register, upload};
    use server::handlers;
    use server::store::Store;
    use shared::frame::{recv_frame, send_frame};
    use shared::messages::*;
    use tokio::io::duplex;

    /// Simulates a server responding to one message.
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

    // OPAQUE registration = 2 server round trips.
    // OPAQUE login       = 2 server round trips.

    #[tokio::test]
    async fn test_register_login_roundtrip() {
        let store = Store::new_random();
        let (mut client, mut server) = duplex(65536);

        tokio::spawn(async move {
            server_respond(&mut server, &store).await; // OpaqueRegStart  → OpaqueRegResp
            server_respond(&mut server, &store).await; // OpaqueRegFinish → RegisterOk
            server_respond(&mut server, &store).await; // OpaqueLoginStart  → OpaqueLoginResp
            server_respond(&mut server, &store).await; // OpaqueLoginFinish → LoginOk
        });

        register(&mut client, "alice", "password123").await.unwrap();
        let session = login(&mut client, "alice", "password123").await.unwrap();
        assert_eq!(session.username, "alice");
    }

    #[tokio::test]
    async fn test_wrong_password_fails() {
        let store = Store::new_random();
        let (mut client, mut server) = duplex(65536);

        tokio::spawn(async move {
            server_respond(&mut server, &store).await; // OpaqueRegStart  → OpaqueRegResp
            server_respond(&mut server, &store).await; // OpaqueRegFinish → RegisterOk
            server_respond(&mut server, &store).await; // OpaqueLoginStart → OpaqueLoginResp
            // Wrong password: client detects it locally; OpaqueLoginFinish is never sent.
        });

        register(&mut client, "alice", "correctpassword")
            .await
            .unwrap();
        let result = login(&mut client, "alice", "wrongpassword").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_upload_download_roundtrip() {
        let store = Store::new_random();
        let (mut client, mut server) = duplex(65536);

        // register(2) + login(2) + upload(1) + login-again(2) + download(1) = 8
        tokio::spawn(async move {
            for _ in 0..8 {
                server_respond(&mut server, &store).await;
            }
        });

        register(&mut client, "alice", "password123").await.unwrap();
        let session = login(&mut client, "alice", "password123").await.unwrap();

        let tmp = std::env::temp_dir().join("test_upload.txt");
        std::fs::write(&tmp, b"secret file contents").unwrap();

        upload(&mut client, &session, &tmp, "test.txt", 1)
            .await
            .unwrap();

        // Login again for a fresh session (re-using the same duplex stream/store).
        let session2 = login(&mut client, "alice", "password123").await.unwrap();

        let out = std::env::temp_dir().join("test_download.txt");
        download(&mut client, &session2, "test.txt", &out)
            .await
            .unwrap();

        let contents = std::fs::read(&out).unwrap();
        assert_eq!(contents, b"secret file contents");

        std::fs::remove_file(&tmp).unwrap();
        std::fs::remove_file(&out).unwrap();
    }

    #[tokio::test]
    async fn test_list_shows_decrypted_filenames() {
        let store = Store::new_random();
        let (mut client, mut server) = duplex(65536);

        // register(2) + login(2) + upload(1) + list(1) = 6
        tokio::spawn(async move {
            for _ in 0..6 {
                server_respond(&mut server, &store).await;
            }
        });

        register(&mut client, "alice", "password123").await.unwrap();
        let session = login(&mut client, "alice", "password123").await.unwrap();

        let tmp = std::env::temp_dir().join("list_test.txt");
        std::fs::write(&tmp, b"data").unwrap();
        upload(&mut client, &session, &tmp, "myfile.txt", 1)
            .await
            .unwrap();

        let files = list(&mut client, &session).await.unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, "myfile.txt");

        std::fs::remove_file(&tmp).unwrap();
    }

    /// The same password must produce the same file-operation keys on every login.
    #[tokio::test]
    async fn test_export_key_consistency() {
        let store = Store::new_random();
        let (mut client, mut server) = duplex(65536);

        // register(2) + login(2) + login-again(2) = 6
        tokio::spawn(async move {
            for _ in 0..6 {
                server_respond(&mut server, &store).await;
            }
        });

        register(&mut client, "alice", "password123").await.unwrap();
        let s1 = login(&mut client, "alice", "password123").await.unwrap();
        let s2 = login(&mut client, "alice", "password123").await.unwrap();

        assert_eq!(s1.enc_key, s2.enc_key);
        assert_eq!(s1.mac_key, s2.mac_key);
        assert_eq!(s1.meta_key, s2.meta_key);
        assert_eq!(
            s1.signing_key.verifying_key().to_bytes(),
            s2.signing_key.verifying_key().to_bytes()
        );
    }
}
