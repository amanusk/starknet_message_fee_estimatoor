mod config;
mod server;
mod simulator;

use config::Settings;
use server::RpcServer;
use tracing::{error, info};
use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load configuration
    let settings = Settings::new()?;
    info!("Loaded configuration: {:?}", settings);

    // Get server address
    let addr = settings.server_addr()?;

    // Create and start RPC server
    let rpc_server = RpcServer::new()?;

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
