use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Settings {
    pub server: ServerConfig,
    pub ethereum: EthereumConfig,
    pub starknet: StarknetConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EthereumConfig {
    pub endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StarknetConfig {
    pub endpoint: String,
}

impl Settings {
    /// Load settings from configuration sources
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration cannot be loaded or parsed
    pub fn new() -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            // Start with default values
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 8080)?
            .set_default("ethereum.endpoint", "http://localhost:8545")?
            .set_default(
                "starknet.endpoint",
                "https://starknet-mainnet.public.blastapi.io",
            )?
            // Add optional config file (if it exists)
            .add_source(config::File::with_name("config").required(false))
            // Override with environment variables (with APP_ prefix)
            .add_source(config::Environment::with_prefix("APP"))
            .build()?;

        settings.try_deserialize()
    }

    /// Parse the server address from host and port
    ///
    /// # Errors
    ///
    /// Returns an error if the host and port cannot be parsed as a valid socket address
    pub fn server_addr(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        format!("{}:{}", self.server.host, self.server.port).parse()
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self::new().expect("Failed to load default configuration")
    }
}
