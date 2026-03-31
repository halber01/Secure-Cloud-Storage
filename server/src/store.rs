use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// Data records
#[derive(Clone)]
pub struct UserRecord {
    pub salt: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Clone)]
pub struct FileRecord {
    pub ciphertext: Vec<u8>,
    pub encrypted_metadata: Vec<u8>,
    pub version: u64,
    pub signature: Vec<u8>,
}

#[derive(Clone)]
pub struct Store {
    users: Arc<RwLock<HashMap<String, UserRecord>>>,
    files: Arc<RwLock<HashMap<(String, Vec<u8>), FileRecord>>>,
    sessions: Arc<RwLock<HashMap<Vec<u8>, String>>>,
    challenges: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl Store {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            files: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    // Users
    /// Returns false if username already exists
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

    // Challenges
    /// Store a one-time login challenge nonce for a user
    pub fn store_challenge(&self, username: String, nonce: Vec<u8>) {
        self.challenges.write().unwrap().insert(username, nonce);
    }

    /// Take consumes the challenge. Prevents replay attacks
    pub fn take_challenge(&self, username: &str) -> Option<Vec<u8>> {
        self.challenges.write().unwrap().remove(username)
    }

    // Sessions
    pub fn create_session(&self, token: Vec<u8>, username: String) {
        self.sessions.write().unwrap().insert(token, username);
    }

    /// Returns the username for a valid session token
    pub fn resolve_session(&self, token: &[u8]) -> Option<String> {
        self.sessions.read().unwrap().get(token).cloned()
    }

    #[allow(dead_code)]
    pub fn delete_session(&self, token: &[u8]) {
        self.sessions.write().unwrap().remove(token);
    }

    // Files

    /// Stores a file, enforcing monotonically increasing versions
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

    /// Returns all file entries for a user
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> Store {
        Store::new()
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
        let record = UserRecord {
            salt: vec![0u8; 16],
            public_key: vec![1u8; 32],
        };
        assert!(store.register_user("alice".to_string(), record));
        assert!(store.get_user("alice").is_some());
    }

    #[test]
    fn test_duplicate_registration_fails() {
        let store = make_store();
        let record = UserRecord {
            salt: vec![0u8; 16],
            public_key: vec![1u8; 32],
        };
        store.register_user("alice".to_string(), record.clone());
        assert!(!store.register_user("alice".to_string(), record));
    }

    #[test]
    fn test_challenge_consumed_after_use() {
        let store = make_store();
        store.store_challenge("alice".to_string(), vec![1, 2, 3]);
        assert!(store.take_challenge("alice").is_some()); // first use works
        assert!(store.take_challenge("alice").is_none()); // second use fails
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
