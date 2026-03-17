// Network configuration for the server
pub struct Config {
    pub address: &'static str,
    pub port: u16,
}

pub const SERVER_CONFIG: Config = Config {
    address: "127.0.0.1",
    port: 8443,
};