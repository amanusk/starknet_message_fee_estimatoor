use crate::simulator::{NetworkConfig, TransactionData, TransactionSimulator};
use eyre::{eyre, Result};
use jsonrpsee::server::ServerBuilder;
use jsonrpsee::RpcModule;
use std::net::SocketAddr;
use tracing::{error, info};

pub struct RpcServer {
    simulator: TransactionSimulator,
}

impl RpcServer {
    pub fn new() -> Result<Self> {
        // Initialize simulator with default network configuration
        let network_config = NetworkConfig::default();
        let simulator = TransactionSimulator::new(network_config)?;

        Ok(Self { simulator })
    }

    pub async fn start(self, addr: SocketAddr) -> Result<()> {
        let server = ServerBuilder::default().build(addr).await?;

        // Move simulator to shared state for RPC methods
        let simulator = std::sync::Arc::new(tokio::sync::Mutex::new(self.simulator));
        let mut module = RpcModule::new(());

        // Register estimate_fee method
        {
            let simulator_clone = simulator.clone();
            module.register_async_method("estimate_fee", move |params, _| {
                let simulator = simulator_clone.clone();
                async move {
                    info!("estimate_fee called with params: {:?}", params);

                    // Parse transaction data from params
                    let transaction_data = match parse_transaction_params(params) {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("Failed to parse transaction parameters: {}", e);
                            return serde_json::json!({
                                "error": {
                                    "code": -32602,
                                    "message": "Invalid parameters",
                                    "data": e.to_string()
                                }
                            });
                        }
                    };

                    // Estimate fee using simulator
                    let simulator_guard = simulator.lock().await;
                    match simulator_guard.estimate_fee(transaction_data).await {
                        Ok(estimated_gas) => {
                            serde_json::json!({
                                "result": {
                                    "gas_estimate": estimated_gas,
                                    "status": "success"
                                }
                            })
                        }
                        Err(e) => {
                            error!("Fee estimation failed: {}", e);
                            serde_json::json!({
                                "error": {
                                    "code": -32603,
                                    "message": "Fee estimation failed",
                                    "data": e.to_string()
                                }
                            })
                        }
                    }
                }
            })?;
        }

        // Register simulate_transaction method
        {
            let simulator_clone = simulator.clone();
            module.register_async_method("simulate_transaction", move |params, _| {
                let simulator = simulator_clone.clone();
                async move {
                    info!("simulate_transaction called with params: {:?}", params);

                    // Parse transaction data from params
                    let transaction_data = match parse_transaction_params(params) {
                        Ok(tx) => tx,
                        Err(e) => {
                            error!("Failed to parse transaction parameters: {}", e);
                            return serde_json::json!({
                                "error": {
                                    "code": -32602,
                                    "message": "Invalid parameters",
                                    "data": e.to_string()
                                }
                            });
                        }
                    };

                    // Simulate transaction
                    let simulator_guard = simulator.lock().await;
                    match simulator_guard.simulate_transaction(transaction_data).await {
                        Ok(result) => {
                            serde_json::json!({
                                "result": result
                            })
                        }
                        Err(e) => {
                            error!("Transaction simulation failed: {}", e);
                            serde_json::json!({
                                "error": {
                                    "code": -32603,
                                    "message": "Transaction simulation failed",
                                    "data": e.to_string()
                                }
                            })
                        }
                    }
                }
            })?;
        }

        let handle = server.start(module);

        info!("JSON-RPC server started on {}", addr);

        // Keep the server running
        handle.stopped().await;

        Ok(())
    }
}

/// Parse transaction parameters from JSON-RPC params
fn parse_transaction_params(params: jsonrpsee::types::Params) -> Result<TransactionData> {
    // TODO: Implement proper parameter parsing based on your RPC interface specification
    // This is a placeholder implementation that expects specific parameter structure

    let params_value: serde_json::Value = params.parse()?;

    // Try to extract transaction data from params
    // This assumes params is either an array with transaction object or a single transaction object
    let tx_data = if params_value.is_array() {
        params_value
            .as_array()
            .and_then(|arr| arr.first())
            .ok_or_else(|| eyre!("Missing transaction data in parameters"))?
    } else {
        &params_value
    };

    // Extract fields with defaults for missing values
    let from = tx_data
        .get("from")
        .and_then(|v| v.as_str())
        .unwrap_or("0x0000000000000000000000000000000000000000")
        .to_string();

    let to = tx_data
        .get("to")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let value = tx_data
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("0")
        .to_string();

    let data = tx_data
        .get("data")
        .and_then(|v| v.as_str())
        .map(|s| hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap_or_default())
        .unwrap_or_default();

    let gas_limit = tx_data
        .get("gas")
        .or_else(|| tx_data.get("gasLimit"))
        .and_then(|v| v.as_u64())
        .unwrap_or(21000);

    let gas_price = tx_data
        .get("gasPrice")
        .and_then(|v| v.as_str())
        .unwrap_or("20000000000")
        .to_string();

    let nonce = tx_data.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0);

    Ok(TransactionData {
        from,
        to,
        value,
        data,
        gas_limit,
        gas_price,
        nonce,
    })
}
