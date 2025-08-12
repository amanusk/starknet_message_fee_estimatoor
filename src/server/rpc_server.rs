use crate::fee_estimator::{StarknetFeeEstimator, StarknetFeeEstimatorConfig};
use crate::simulator::transaction_simulator::L1ToL2MessageSentEvent;
use crate::simulator::{NetworkConfig, TransactionData, TransactionSimulator};
use eyre::{eyre, Result};
use jsonrpsee::server::ServerBuilder;
use jsonrpsee::RpcModule;
use std::net::SocketAddr;
use tracing::{error, info};

pub struct RpcServer {
    simulator: TransactionSimulator,
    fee_estimator: StarknetFeeEstimator,
}

impl RpcServer {
    pub fn new() -> Result<Self> {
        // Initialize simulator with default network configuration
        let network_config = NetworkConfig::default();
        let simulator = TransactionSimulator::new(network_config)?;

        // Initialize Starknet fee estimator with default configuration
        let fee_estimator_config = StarknetFeeEstimatorConfig::default();
        let fee_estimator = StarknetFeeEstimator::new(fee_estimator_config)?;

        Ok(Self {
            simulator,
            fee_estimator,
        })
    }

    pub fn new_with_config(l1_rpc_url: String, starknet_rpc_url: String) -> Result<Self> {
        // Initialize simulator with custom network configuration
        let network_config = NetworkConfig {
            l1_rpc_url,
            block_number: None,
        };
        let simulator = TransactionSimulator::new(network_config)?;

        // Initialize Starknet fee estimator with custom RPC URL
        let fee_estimator = StarknetFeeEstimator::from_url(&starknet_rpc_url)?;

        Ok(Self {
            simulator,
            fee_estimator,
        })
    }

    pub async fn start(self, addr: SocketAddr) -> Result<()> {
        let server = ServerBuilder::default().build(addr).await?;

        // Move simulator and fee estimator to shared state for RPC methods
        let simulator = std::sync::Arc::new(tokio::sync::Mutex::new(self.simulator));
        let fee_estimator = std::sync::Arc::new(tokio::sync::Mutex::new(self.fee_estimator));
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

        // Register estimate_l1_to_l2_message_fees method
        {
            let fee_estimator_clone = fee_estimator.clone();
            module.register_async_method("estimate_l1_to_l2_message_fees", move |params, _| {
                let fee_estimator = fee_estimator_clone.clone();
                async move {
                    info!(
                        "estimate_l1_to_l2_message_fees called with params: {:?}",
                        params
                    );

                    // Parse L1 to L2 message events from params
                    let message_events = match parse_l1_to_l2_message_params(params) {
                        Ok(events) => events,
                        Err(e) => {
                            error!("Failed to parse L1 to L2 message parameters: {}", e);
                            return serde_json::json!({
                                "error": {
                                    "code": -32602,
                                    "message": "Invalid parameters",
                                    "data": e.to_string()
                                }
                            });
                        }
                    };

                    // Estimate fees using Starknet fee estimator
                    let fee_estimator_guard = fee_estimator.lock().await;
                    match fee_estimator_guard
                        .estimate_messages_fee(message_events)
                        .await
                    {
                        Ok(summary) => {
                            serde_json::json!({
                                "result": summary
                            })
                        }
                        Err(e) => {
                            error!("L1 to L2 message fee estimation failed: {}", e);
                            serde_json::json!({
                                "error": {
                                    "code": -32603,
                                    "message": "L1 to L2 message fee estimation failed",
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

/// Parse L1 to L2 message event parameters from JSON-RPC params
fn parse_l1_to_l2_message_params(
    params: jsonrpsee::types::Params,
) -> Result<Vec<L1ToL2MessageSentEvent>> {
    use starknet::core::types::{EthAddress, Felt};

    let params_value: serde_json::Value = params.parse()?;

    // Try to extract message events from params
    // This assumes params is either an array with message objects or a single message list
    let messages_data = if params_value.is_array() {
        params_value
            .as_array()
            .and_then(|arr| arr.first())
            .ok_or_else(|| eyre!("Missing message events data in parameters"))?
    } else {
        &params_value
    };

    // Extract the "messages" array from the parameter
    let messages_array = messages_data
        .get("messages")
        .and_then(|v| v.as_array())
        .ok_or_else(|| eyre!("Expected 'messages' array in parameters"))?;

    let mut events = Vec::new();

    for (index, message) in messages_array.iter().enumerate() {
        let from_address_str = message
            .get("from_address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| eyre!("Missing 'from_address' in message {}", index))?;

        let from_address = EthAddress::from_hex(from_address_str).map_err(|e| {
            eyre!(
                "Invalid from_address '{}' in message {}: {}",
                from_address_str,
                index,
                e
            )
        })?;

        // Extract l2_address field
        let l2_address_str = message
            .get("l2_address")
            .and_then(|v| v.as_str())
            .ok_or_else(|| eyre!("Missing 'l2_address' in message {}", index))?;

        let l2_address = Felt::from_hex(l2_address_str).map_err(|e| {
            eyre!(
                "Invalid l2_address '{}' in message {}: {}",
                l2_address_str,
                index,
                e
            )
        })?;

        // Extract selector field
        let selector_str = message
            .get("selector")
            .and_then(|v| v.as_str())
            .ok_or_else(|| eyre!("Missing 'selector' in message {}", index))?;

        let selector = Felt::from_hex(selector_str).map_err(|e| {
            eyre!(
                "Invalid selector '{}' in message {}: {}",
                selector_str,
                index,
                e
            )
        })?;

        // Extract payload field
        let payload_array = message
            .get("payload")
            .and_then(|v| v.as_array())
            .ok_or_else(|| eyre!("Missing 'payload' array in message {}", index))?;

        let mut payload = Vec::new();
        for (payload_index, payload_item) in payload_array.iter().enumerate() {
            let payload_str = payload_item.as_str().ok_or_else(|| {
                eyre!(
                    "Invalid payload item {} in message {}: expected string",
                    payload_index,
                    index
                )
            })?;

            let payload_felt = Felt::from_hex(payload_str).map_err(|e| {
                eyre!(
                    "Invalid payload item '{}' in message {}: {}",
                    payload_str,
                    index,
                    e
                )
            })?;

            payload.push(payload_felt);
        }

        events.push(L1ToL2MessageSentEvent {
            from_address,
            l2_address,
            selector,
            payload,
        });
    }

    Ok(events)
}
