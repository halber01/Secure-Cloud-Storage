// Argon2id parameters
pub const ARGON2_MEMORY_KIB: u32 = 65536;  // 64 MB
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 1;

// Key sizes
pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

// Framing
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MB