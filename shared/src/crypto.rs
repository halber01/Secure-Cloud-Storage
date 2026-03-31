use crate::constants::*;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use argon2::password_hash::rand_core::RngCore;
use argon2::{Argon2, Params, Version};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Generates 16 random bytes for use as Argon2 salt
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derives a 32-byte master key from password + salt using Argon2id
pub fn derive_master_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    let params = Params::new(ARGON2_MEMORY_KIB, 3, 1, Some(KEY_LEN)).map_err(|e| e.to_string())?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

// Subkey derivation

/// Derives a 32-byte subkey from master_key using HKDF-SHA256.
pub fn derive_subkey(master_key: &[u8], label: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(label, &mut okm).expect("HKDF expand failed");
    okm
}

// File ID

/// Computes a deterministic file ID: HMAC-SHA256(mac_key, filename)
/// Server sees only encrypted filename
pub fn compute_file_id(mac_key: &[u8], filename: &str) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(mac_key).expect("HMAC accepts any key size");
    mac.update(filename.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

// Encrypt

/// Encrypts plaintext with AES-256-GCM
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| e.to_string())?;
    // prepend nonce so decrypt() knows what to use
    let mut output = Vec::new();
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

// Decrypt

/// Decrypts a blob produced by encrypt().
/// Splits off the first 12 bytes as nonce, decrypts the rest.
/// Returns Err if the key is wrong or data was tampered with.
pub fn decrypt(key: &[u8; KEY_LEN], blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < 12 {
        return Err("Ciphertext too short".to_string());
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed — wrong key or tampered data".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0u8; 32]; // dummy key, all zeros
        let plaintext = b"hello secret world";

        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32]; // different key
        let plaintext = b"secret";

        let ciphertext = encrypt(&key1, plaintext).unwrap();
        let decrypted = decrypt(&key2, &ciphertext);
        assert!(decrypted.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0u8; 32];
        let mut ciphertext = encrypt(&key, b"secret").unwrap();
        ciphertext[15] ^= 0xFF; // flip some bits
        assert!(decrypt(&key, &ciphertext).is_err());
    }

    #[test]
    fn test_subkey_domain_separation() {
        let master = [0u8; 32];
        let enc_key = derive_subkey(&master, HKDF_ENC_LABEL);
        let mac_key = derive_subkey(&master, HKDF_MAC_LABEL);
        let meta_key = derive_subkey(&master, HKDF_META_LABEL);
        assert_ne!(enc_key, mac_key);
        assert_ne!(mac_key, meta_key);
        assert_ne!(enc_key, meta_key);
    }
}
