use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// Structs
#[derive(Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
}

#[derive(Serialize, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TlsConfig {
    pub mode: TlsMode, // "saas" or "selfhosted"
    #[serde(default)]
    pub ca_fingerprint: String, // empty for SaaS
}

#[derive(Serialize, Deserialize)]
pub enum TlsMode {
    Saas,
    SelfHosted,
}

// Defaults
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            tls: TlsConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1".to_string(),
            port: 8443,
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mode: TlsMode::Saas,
            ca_fingerprint: String::new(),
        }
    }
}

// Loading
pub fn load_config() -> ClientConfig {
    load_config_from(config_path())
}

pub fn load_config_from(path: PathBuf) -> ClientConfig {
    match std::fs::read_to_string(&path) {
        Ok(contents) => toml::from_str(&contents).unwrap_or_default(),
        Err(_) => ClientConfig::default(),
    }
}

fn config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("secure-cloud")
        .join("config.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_when_no_file() {
        let config = load_config_from(PathBuf::from("/nonexistent/path/config.toml"));
        assert_eq!(config.server.address, "127.0.0.1");
        assert_eq!(config.server.port, 8443);
    }

    #[test]
    fn test_loads_from_file() {
        let temp_path = std::env::temp_dir().join("test_config.toml");

        // write a config with non-default values
        std::fs::write(
            &temp_path,
            r#"
        [server]
        address = "192.168.1.100"
        port = 9000

        [tls]
        mode = "SelfHosted"
        ca-fingerprint = "abc123"
    "#,
        )
        .unwrap();

        let config = load_config_from(temp_path.clone());
        let contents = std::fs::read_to_string(&temp_path).unwrap();

        // check toml parses correctly
        let parsed: Result<ClientConfig, toml::de::Error> = toml::from_str(&contents);
        match &parsed {
            Ok(_) => println!("Parse ok"),
            Err(e) => println!("Parse error: {}", e),
        }

        // assert non-default values were loaded
        assert_eq!(config.server.address, "192.168.1.100");
        assert_eq!(config.server.port, 9000);
        assert_eq!(config.tls.ca_fingerprint, "abc123");

        std::fs::remove_file(temp_path).unwrap();
    }
}
