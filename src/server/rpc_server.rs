use jsonrpsee::server::ServerBuilder;
use jsonrpsee::RpcModule;
use std::net::SocketAddr;
use tracing::info;

pub struct RpcServer;

impl RpcServer {
    pub fn new() -> Self {
        Self
    }

    pub async fn start(self, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let server = ServerBuilder::default().build(addr).await?;

        let mut module = RpcModule::new(());

        // Register estimate_fee method
        module.register_async_method("estimate_fee", |_params, _| async move {
            info!("estimate_fee called");

            // TODO: Implement actual fee estimation logic
            serde_json::json!({
                "status": "success",
                "message": "Fee estimation not yet implemented"
            })
        })?;

        // Register simulate_transaction method
        module.register_async_method("simulate_transaction", |_params, _| async move {
            info!("simulate_transaction called");

            // TODO: Implement transaction simulation logic
            serde_json::json!({
                "status": "success",
                "message": "Transaction simulation not yet implemented"
            })
        })?;

        let handle = server.start(module);

        info!("JSON-RPC server started on {}", addr);

        // Keep the server running
        handle.stopped().await;

        Ok(())
    }
}
