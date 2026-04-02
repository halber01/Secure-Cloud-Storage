use crate::constants::*;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use opaque_ke::CipherSuite;
use sha2::{Sha256, Sha512};

// ── OPAQUE cipher suite ───────────────────────────────────────────────────────

/// The OPAQUE cipher suite used throughout the system:
///   OPRF  – Ristretto255
///   KE    – Triple-DH over Ristretto255 with SHA-512
///   KSF   – Argon2id (via opaque-ke's built-in KSF)
pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, Sha512>;
    type Ksf = opaque_ke::argon2::Argon2<'static>;
}

// ── HKDF subkey derivation ────────────────────────────────────────────────────

/// Derives a 32-byte subkey from master_key using HKDF-SHA256.
/// master_key is the 64-byte export_key from OPAQUE.
pub fn derive_subkey(master_key: &[u8], label: &[u8]) -> [u8; KEY_LEN] {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(label, &mut okm).expect("HKDF expand failed");
    okm
}

// ── File ID ───────────────────────────────────────────────────────────────────

/// Computes a deterministic file ID: HMAC-SHA256(mac_key, filename).
/// The server sees only the opaque ID, never the plaintext filename.
pub fn compute_file_id(mac_key: &[u8], filename: &str) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(mac_key).expect("HMAC accepts any key size");
    mac.update(filename.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

// ── AES-256-GCM encryption ────────────────────────────────────────────────────

/// Encrypts plaintext with AES-256-GCM.
/// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes).
pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| e.to_string())?;
    let mut output = Vec::new();
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

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
        let key = [0u8; 32];
        let plaintext = b"hello secret world";

        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [0u8; 32];
        let key2 = [1u8; 32];
        let plaintext = b"secret";

        let ciphertext = encrypt(&key1, plaintext).unwrap();
        let decrypted = decrypt(&key2, &ciphertext);
        assert!(decrypted.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = [0u8; 32];
        let mut ciphertext = encrypt(&key, b"secret").unwrap();
        ciphertext[15] ^= 0xFF;
        assert!(decrypt(&key, &ciphertext).is_err());
    }

    #[test]
    fn test_subkey_domain_separation() {
        let master = [0u8; 64]; // export_key is 64 bytes
        let enc_key = derive_subkey(&master, HKDF_ENC_LABEL);
        let mac_key = derive_subkey(&master, HKDF_MAC_LABEL);
        let meta_key = derive_subkey(&master, HKDF_META_LABEL);
        assert_ne!(enc_key, mac_key);
        assert_ne!(mac_key, meta_key);
        assert_ne!(enc_key, meta_key);
    }
}
