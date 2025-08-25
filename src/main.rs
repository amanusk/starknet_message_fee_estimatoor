mod api;
mod config;
mod fee_estimator;
mod logging;
mod server;
mod simulator;

use config::Settings;
use eyre::Result;
use log::{error, info};
use server::RpcServer;

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration first
    let settings = Settings::new()?;

    // Initialize logging with configuration
    logging::init_logging(&settings.logging)?;

    info!("Loaded configuration: {:?}", settings);

    // Get server address
    let addr = settings.server_addr()?;

    // Create and start RPC server with configuration
    let rpc_server =
        RpcServer::new_with_config(&settings.ethereum.endpoint, &settings.starknet.endpoint)?;

    info!("Starting server on {}", addr);

    // Start server with graceful shutdown
    tokio::select! {
        result = rpc_server.start(addr) => {
            if let Err(e) = result {
                error!("Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down gracefully");
        }
    }

    info!("Server stopped");
    Ok(())
}
