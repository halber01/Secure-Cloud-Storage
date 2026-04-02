use opaque_ke::ServerSetup;
use shared::crypto::DefaultCipherSuite;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

type FileStore = Arc<RwLock<HashMap<(String, Vec<u8>), FileRecord>>>;

// ── Data records ──────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct UserRecord {
    /// Serialized OPAQUE PasswordFile — replaces the old (salt, public_key) pair.
    pub password_file: Vec<u8>,
    /// Ed25519 public key derived from export_key via HKDF.
    /// Used by the server to verify file-operation signatures.
    pub public_key: Vec<u8>,
}

#[derive(Clone)]
pub struct FileRecord {
    pub ciphertext: Vec<u8>,
    pub encrypted_metadata: Vec<u8>,
    pub version: u64,
    pub signature: Vec<u8>,
}

// ── Store ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Store {
    /// OPAQUE server setup (static keypair + OPRF seed). Loaded once at startup.
    server_setup: Arc<ServerSetup<DefaultCipherSuite>>,
    users: Arc<RwLock<HashMap<String, UserRecord>>>,
    files: FileStore,
    sessions: Arc<RwLock<HashMap<Vec<u8>, String>>>,
    /// Serialized ServerLogin state keyed by username.
    /// Stored between OpaqueLoginStart and OpaqueLoginFinish for the same connection.
    login_states: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl Store {
    pub fn new(server_setup: ServerSetup<DefaultCipherSuite>) -> Self {
        Self {
            server_setup: Arc::new(server_setup),
            users: Arc::new(RwLock::new(HashMap::new())),
            files: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            login_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generates a fresh random ServerSetup and wraps it in a Store.
    /// Useful for tests. Production code should use `Store::new` with a
    /// persisted ServerSetup so registered passwords remain valid across restarts.
    pub fn new_random() -> Self {
        use opaque_ke::rand::rngs::OsRng;
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);
        Self::new(server_setup)
    }

    pub fn server_setup(&self) -> &ServerSetup<DefaultCipherSuite> {
        &self.server_setup
    }

    // ── Users ─────────────────────────────────────────────────────────────────

    /// Returns false if the username is already registered.
    pub fn register_user(&self, username: String, record: UserRecord) -> bool {
        let mut users = self.users.write().unwrap();
        if users.contains_key(&username) {
            return false;
        }
        users.insert(username, record);
        true
    }

    pub fn get_user(&self, username: &str) -> Option<UserRecord> {
        self.users.read().unwrap().get(username).cloned()
    }

    // ── OPAQUE login state ────────────────────────────────────────────────────

    /// Persists the serialized ServerLogin intermediate state for a user.
    /// Called after OpaqueLoginStart; consumed by OpaqueLoginFinish.
    pub fn store_login_state(&self, username: String, state: Vec<u8>) {
        self.login_states.write().unwrap().insert(username, state);
    }

    /// Takes (removes) the serialized ServerLogin state for a user.
    /// Prevents replay: a second OpaqueLoginFinish with the same username will fail.
    pub fn take_login_state(&self, username: &str) -> Option<Vec<u8>> {
        self.login_states.write().unwrap().remove(username)
    }

    // ── Sessions ──────────────────────────────────────────────────────────────

    pub fn create_session(&self, token: Vec<u8>, username: String) {
        self.sessions.write().unwrap().insert(token, username);
    }

    /// Returns the username for a valid session token.
    pub fn resolve_session(&self, token: &[u8]) -> Option<String> {
        self.sessions.read().unwrap().get(token).cloned()
    }

    #[allow(dead_code)]
    pub fn delete_session(&self, token: &[u8]) {
        self.sessions.write().unwrap().remove(token);
    }

    // ── Files ─────────────────────────────────────────────────────────────────

    /// Stores a file, enforcing monotonically increasing versions.
    pub fn put_file(
        &self,
        username: String,
        file_id: Vec<u8>,
        record: FileRecord,
    ) -> Result<(), String> {
        let mut files = self.files.write().unwrap();
        let key = (username, file_id);
        if let Some(existing) = files.get(&key)
            && record.version <= existing.version
        {
            return Err(format!(
                "Version rollback rejected: got {}, have {}",
                record.version, existing.version
            ));
        }
        files.insert(key, record);
        Ok(())
    }

    pub fn get_file(&self, username: &str, file_id: &[u8]) -> Option<FileRecord> {
        self.files
            .read()
            .unwrap()
            .get(&(username.to_string(), file_id.to_vec()))
            .cloned()
    }

    pub fn delete_file(&self, username: &str, file_id: &[u8]) -> bool {
        self.files
            .write()
            .unwrap()
            .remove(&(username.to_string(), file_id.to_vec()))
            .is_some()
    }

    /// Returns all file entries for a user as (file_id, encrypted_metadata, version).
    pub fn list_files(&self, username: &str) -> Vec<(Vec<u8>, Vec<u8>, u64)> {
        self.files
            .read()
            .unwrap()
            .iter()
            .filter(|((u, _), _)| u == username)
            .map(|((_, fid), rec)| (fid.clone(), rec.encrypted_metadata.clone(), rec.version))
            .collect()
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new_random()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> Store {
        Store::new_random()
    }

    fn dummy_user() -> UserRecord {
        UserRecord {
            password_file: vec![0u8; 64],
            public_key: vec![1u8; 32],
        }
    }

    fn dummy_file(version: u64) -> FileRecord {
        FileRecord {
            ciphertext: vec![1, 2, 3],
            encrypted_metadata: vec![4, 5, 6],
            version,
            signature: vec![7, 8, 9],
        }
    }

    #[test]
    fn test_register_and_get_user() {
        let store = make_store();
        assert!(store.register_user("alice".to_string(), dummy_user()));
        assert!(store.get_user("alice").is_some());
    }

    #[test]
    fn test_duplicate_registration_fails() {
        let store = make_store();
        store.register_user("alice".to_string(), dummy_user());
        assert!(!store.register_user("alice".to_string(), dummy_user()));
    }

    #[test]
    fn test_login_state_consumed_after_use() {
        let store = make_store();
        store.store_login_state("alice".to_string(), vec![1, 2, 3]);
        assert!(store.take_login_state("alice").is_some());
        assert!(store.take_login_state("alice").is_none()); // second take fails
    }

    #[test]
    fn test_version_rollback_rejected() {
        let store = make_store();
        store
            .put_file("alice".to_string(), vec![0], dummy_file(2))
            .unwrap();
        let result = store.put_file("alice".to_string(), vec![0], dummy_file(1));
        assert!(result.is_err());
    }

    #[test]
    fn test_version_update_accepted() {
        let store = make_store();
        store
            .put_file("alice".to_string(), vec![0], dummy_file(1))
            .unwrap();
        assert!(
            store
                .put_file("alice".to_string(), vec![0], dummy_file(2))
                .is_ok()
        );
    }
}
