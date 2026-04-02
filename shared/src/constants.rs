// Key sizes
pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

// Framing
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MB

// HKDF labels
pub const HKDF_ENC_LABEL: &[u8] = b"enc-key-v1";
pub const HKDF_MAC_LABEL: &[u8] = b"mac-key-v1";
pub const HKDF_META_LABEL: &[u8] = b"meta-key-v1";
pub const HKDF_SIGN_LABEL: &[u8] = b"sign-key-v1";
