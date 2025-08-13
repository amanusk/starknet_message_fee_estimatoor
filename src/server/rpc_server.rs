use crate::api::{ApiError, ApiErrorCode, ApiResponse};
use crate::fee_estimator::{StarknetFeeEstimator, StarknetFeeEstimatorConfig};
use crate::simulator::transaction_simulator::L1ToL2MessageSentEvent;
use crate::simulator::{NetworkConfig, TransactionSimulator, UnsignedTransactionData};
use alloy::consensus::TxEnvelope;
use alloy::eips::Decodable2718;
use alloy::primitives::Bytes;
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
    #[allow(dead_code)]
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
        let network_config = NetworkConfig { l1_rpc_url };
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
                            let api_error = ApiError::with_details(
                                ApiErrorCode::InvalidInputFormat,
                                "Invalid input format",
                                e.to_string()
                            );
                            let response = ApiResponse::error(api_error);
                            return serde_json::to_value(response).unwrap_or_else(|_| {
                                serde_json::json!({"error": {"code": "internal_error", "message": "Failed to serialize response"}})
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
                            let response = ApiResponse::success(summary);
                            serde_json::to_value(response).unwrap_or_else(|_| {
                                serde_json::json!({"error": {"code": "internal_error", "message": "Failed to serialize response"}})
                            })
                        }
                        Err(e) => {
                            error!("L1 to L2 message fee estimation failed: {}", e);
                            let api_error = ApiError::with_details(
                                ApiErrorCode::FeeEstimationFailed,
                                "Failed to estimate fee",
                                e.to_string()
                            );
                            let response = ApiResponse::error(api_error);
                            serde_json::to_value(response).unwrap_or_else(|_| {
                                serde_json::json!({"error": {"code": "internal_error", "message": "Failed to serialize response"}})
                            })
                        }
                    }
                }
            })?;
        }

        // Register estimate_l1_to_l2_message_fees_from_signed_tx method
        {
            let simulator_clone = simulator.clone();
            let fee_estimator_clone = fee_estimator.clone();
            module.register_async_method(
                "estimate_l1_to_l2_message_fees_from_signed_tx",
                move |params, _| {
                    let simulator = simulator_clone.clone();
                    let fee_estimator = fee_estimator_clone.clone();
                    async move {
                        info!(
                        "estimate_l1_to_l2_message_fees_from_signed_tx called with params: {:?}",
                        params
                    );

                        // Parse signed transaction from params
                        let tx_envelope = match parse_signed_transaction_params(params) {
                            Ok(envelope) => envelope,
                            Err(e) => {
                                error!("Failed to parse signed transaction parameters: {}", e);
                                let api_error = ApiError::with_details(
                                    ApiErrorCode::InvalidSignedTransaction,
                                    "Invalid signed transaction",
                                    e.to_string()
                                );
                                let response = ApiResponse::error(api_error);
                                return serde_json::to_value(response).unwrap_or_else(|_| {
                                    serde_json::json!({"error": {"code": "internal_error", "message": "Failed to serialize response"}})
                                });
                            }
                        };

                        // Simulate transaction to get receipt
                        let simulator_guard = simulator.lock().await;
                        let (_, receipt) = match simulator_guard
                            .simulate_tx_envelope_with_receipt(&tx_envelope)
                            .await
                        {
                            Ok(result) => result,
                            Err(e) => {
                                error!("Failed to simulate signed transaction: {}", e);
                                let api_error = ApiError::with_details(
                                    ApiErrorCode::TransactionSimulationFailed,
                                    "Failed to simulate transaction",
                                    e.to_string()
                                );
                                let response = ApiResponse::error(api_error);
                                return serde_json::to_value(response).unwrap_or_else(|_| {
                                    serde_json::json!({"error": {"code": "internal_error", "message": "Failed to serialize response"}})
                                });
                            }
                        };

                        // Parse L1 to L2 message events from receipt
                        let message_events =
                            match simulator_guard.parse_l1_to_l2_message_events(&receipt) {
                                Ok(events) => events,
                                Err(e) => {
                                    error!(
                                        "Failed to parse L1 to L2 message events from receipt: {}",
                                        e
                                    );
                                    let api_error = ApiError::with_details(
                                        ApiErrorCode::TransactionSimulationFailed,
                                        "Failed to parse message events",
                                        e.to_string()
                                    );
                                    let response = ApiResponse::error(api_error);
                                    return serde_json::to_value(response).unwrap_or_else(|_| {
                                        serde_json::json!({"error": {"code": "internal_error", "message": "Failed to serialize response"}})
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
                                let response = ApiResponse::success(summary);
                                serde_json::to_value(response).unwrap_or_else(|_| {
                                    serde_json::json!({"error": {"code": "internal_error", "message": "Failed to serialize response"}})
                                })
                            }
                            Err(e) => {
                                error!("L1 to L2 message fee estimation failed: {}", e);
                                let api_error = ApiError::with_details(
                                    ApiErrorCode::FeeEstimationFailed,
                                    "Failed to estimate fee",
                                    e.to_string()
                                );
                                let response = ApiResponse::error(api_error);
                                serde_json::to_value(response).unwrap_or_else(|_| {
                                    serde_json::json!({"error": {"code": "internal_error", "message": "Failed to serialize response"}})
                                })
                            }
                        }
                    }
                },
            )?;
        }

        // Register estimate_l1_to_l2_message_fees_from_unsigned_tx method
        {
            let simulator_clone = simulator.clone();
            let fee_estimator_clone = fee_estimator.clone();
            module.register_async_method(
                "estimate_l1_to_l2_message_fees_from_unsigned_tx",
                move |params, _| {
                    let simulator = simulator_clone.clone();
                    let fee_estimator = fee_estimator_clone.clone();
                    async move {
                        info!(
                        "estimate_l1_to_l2_message_fees_from_unsigned_tx called with params: {:?}",
                        params
                    );

                        // Parse unsigned transaction data from params
                        let transaction_data = match parse_unsigned_transaction_params(params) {
                            Ok(tx) => tx,
                            Err(e) => {
                                error!("Failed to parse unsigned transaction parameters: {}", e);
                                let api_error = ApiError::with_details(
                                    ApiErrorCode::InvalidUnsignedTransaction,
                                    "Invalid unsigned transaction",
                                    e.to_string()
                                );
                                let response = ApiResponse::error(api_error);
                                return serde_json::to_value(response).unwrap_or_else(|_| {
                                    serde_json::json!({"error": {"code": "internal_error", "message": "Failed to serialize response"}})
                                });
                            }
                        };

                        // Simulate transaction to get receipt
                        let simulator_guard = simulator.lock().await;
                        let (_, receipt) = match simulator_guard
                            .simulate_unsigned_tx_with_receipt(&transaction_data)
                            .await
                        {
                            Ok(result) => result,
                            Err(e) => {
                                error!("Failed to simulate unsigned transaction: {}", e);
                                let api_error = ApiError::with_details(
                                    ApiErrorCode::TransactionSimulationFailed,
                                    "Failed to simulate transaction",
                                    e.to_string()
                                );
                                let response = ApiResponse::error(api_error);
                                return serde_json::to_value(response).unwrap_or_else(|_| {
                                    serde_json::json!({"error": {"code": "internal_error", "message": "Failed to serialize response"}})
                                });
                            }
                        };

                        // Parse L1 to L2 message events from receipt
                        let message_events =
                            match simulator_guard.parse_l1_to_l2_message_events(&receipt) {
                                Ok(events) => events,
                                Err(e) => {
                                    error!(
                                        "Failed to parse L1 to L2 message events from receipt: {}",
                                        e
                                    );
                                    let api_error = ApiError::with_details(
                                        ApiErrorCode::TransactionSimulationFailed,
                                        "Failed to parse message events",
                                        e.to_string()
                                    );
                                    let response = ApiResponse::error(api_error);
                                    return serde_json::to_value(response).unwrap_or_else(|_| {
                                        serde_json::json!({"error": {"code": "internal_error", "message": "Failed to serialize response"}})
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
                                let response = ApiResponse::success(summary);
                                serde_json::to_value(response).unwrap_or_else(|_| {
                                    serde_json::json!({"error": {"code": "internal_error", "message": "Failed to serialize response"}})
                                })
                            }
                            Err(e) => {
                                error!("L1 to L2 message fee estimation failed: {}", e);
                                let api_error = ApiError::with_details(
                                    ApiErrorCode::FeeEstimationFailed,
                                    "Failed to estimate fee",
                                    e.to_string()
                                );
                                let response = ApiResponse::error(api_error);
                                serde_json::to_value(response).unwrap_or_else(|_| {
                                    serde_json::json!({"error": {"code": "internal_error", "message": "Failed to serialize response"}})
                                })
                            }
                        }
                    }
                },
            )?;
        }

        let handle = server.start(module);

        info!("JSON-RPC server started on {}", addr);

        // Keep the server running
        handle.stopped().await;

        Ok(())
    }
}

/// Parse signed transaction parameters from JSON-RPC params
fn parse_signed_transaction_params(params: jsonrpsee::types::Params) -> Result<TxEnvelope> {
    let params_value: serde_json::Value = params.parse()?;

    // Extract raw transaction data from params
    let raw_tx_data = if params_value.is_array() {
        params_value
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .ok_or_else(|| eyre!("Missing raw transaction data in parameters"))?
    } else {
        params_value
            .as_str()
            .ok_or_else(|| eyre!("Expected raw transaction string"))?
    };

    // Remove 0x prefix if present and decode hex
    let raw_bytes = hex::decode(raw_tx_data.strip_prefix("0x").unwrap_or(raw_tx_data))
        .map_err(|e| eyre!("Failed to decode hex transaction data: {}", e))?;

    // Parse the transaction envelope from raw bytes
    let bytes = Bytes::from(raw_bytes);
    TxEnvelope::decode_2718(&mut bytes.as_ref())
        .map_err(|e| eyre!("Failed to decode transaction envelope: {}", e))
}

/// Parse unsigned transaction parameters from JSON-RPC params
fn parse_unsigned_transaction_params(
    params: jsonrpsee::types::Params,
) -> Result<UnsignedTransactionData> {
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

    // Extract fields - from field is required for unsigned transactions
    let from = tx_data
        .get("from")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre!("Missing required 'from' field in unsigned transaction"))?
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
        .and_then(|v| v.as_u64());

    let gas_price = tx_data
        .get("gasPrice")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let max_fee_per_gas = tx_data
        .get("maxFeePerGas")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let max_priority_fee_per_gas = tx_data
        .get("maxPriorityFeePerGas")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let nonce = tx_data.get("nonce").and_then(|v| v.as_u64());

    Ok(UnsignedTransactionData {
        from,
        to,
        value,
        data,
        gas_limit,
        gas_price,
        max_fee_per_gas,
        max_priority_fee_per_gas,
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

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::types::Params;
    use serde_json::json;
    use starknet::core::types::{EthAddress, Felt};

    // Helper function to create Params with proper lifetime management
    fn create_params(value: serde_json::Value) -> Params<'static> {
        let json_string = value.to_string();
        let leaked_str: &'static str = Box::leak(json_string.into_boxed_str());
        Params::new(Some(leaked_str))
    }

    #[test]
    fn test_parse_signed_transaction_params_with_raw_hex() {
        // Test with a simple legacy transaction hex (this is a mock transaction)
        let raw_tx_hex = "0xf86c808509184e72a00082520894d46e8dd67c5d32be8058bb8eb970870f07244567849184e72aa9d46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445678025a0c9cf86333bcb065d971d8e62a6b6b8b2c7c2e4b5a2e3a9e2b8c2e4b5a2e3a9e2c0";

        // Test as string parameter
        let params_json = json!([raw_tx_hex]);
        let params = create_params(params_json);

        let result = parse_signed_transaction_params(params);
        // Should fail because it's not a valid transaction format for this test, but should not panic
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signed_transaction_params_without_0x_prefix() {
        let raw_tx_hex = "f86c808509184e72a00082520894d46e8dd67c5d32be8058bb8eb970870f07244567849184e72aa9d46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445678025a0c9cf86333bcb065d971d8e62a6b6b8b2c7c2e4b5a2e3a9e2b8c2e4b5a2e3a9e2c0";

        let params_json = json!([raw_tx_hex]);
        let params = create_params(params_json);

        let result = parse_signed_transaction_params(params);
        // Should fail because it's not a valid transaction format for this test, but should not panic
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signed_transaction_params_invalid_hex() {
        let invalid_hex = "0xnotvalid";

        let params_json = json!([invalid_hex]);
        let params = create_params(params_json);

        let result = parse_signed_transaction_params(params);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Failed to decode hex transaction data"));
    }

    #[test]
    fn test_parse_signed_transaction_params_missing_data() {
        let params_json = json!([]);
        let params = create_params(params_json);

        let result = parse_signed_transaction_params(params);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Missing raw transaction data"));
    }

    #[test]
    fn test_parse_unsigned_transaction_params_complete() {
        let tx_data = json!({
            "from": "0x742d35Cc6634C0532925a3b8D0b2f0e8e6F5DaBB",
            "to": "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f07244567",
            "value": "0x9184e72a",
            "data": "0xa9059cbb000000000000000000000000000000000000000000000000000000000000000c",
            "gas": 21000,
            "gasPrice": "0x9184e72a00",
            "maxFeePerGas": "0x9184e72a00",
            "maxPriorityFeePerGas": "0x9184e72a",
            "nonce": 1
        });

        let params_json = json!([tx_data]);
        let params = create_params(params_json);

        let result = parse_unsigned_transaction_params(params).unwrap();

        assert_eq!(result.from, "0x742d35Cc6634C0532925a3b8D0b2f0e8e6F5DaBB");
        assert_eq!(
            result.to,
            Some("0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f07244567".to_string())
        );
        assert_eq!(result.value, "0x9184e72a");
        assert_eq!(result.gas_limit, Some(21000));
        assert_eq!(result.gas_price, Some("0x9184e72a00".to_string()));
        assert_eq!(result.max_fee_per_gas, Some("0x9184e72a00".to_string()));
        assert_eq!(
            result.max_priority_fee_per_gas,
            Some("0x9184e72a".to_string())
        );
        assert_eq!(result.nonce, Some(1));
    }

    #[test]
    fn test_parse_unsigned_transaction_params_minimal() {
        let tx_data = json!({
            "from": "0x742d35Cc6634C0532925a3b8D0b2f0e8e6F5DaBB"
        });

        let params_json = json!([tx_data]);
        let params = create_params(params_json);

        let result = parse_unsigned_transaction_params(params).unwrap();

        assert_eq!(result.from, "0x742d35Cc6634C0532925a3b8D0b2f0e8e6F5DaBB");
        assert_eq!(result.to, None);
        assert_eq!(result.value, "0");
        assert_eq!(result.gas_limit, None);
        assert_eq!(result.gas_price, None);
        assert_eq!(result.max_fee_per_gas, None);
        assert_eq!(result.max_priority_fee_per_gas, None);
        assert_eq!(result.nonce, None);
        assert_eq!(result.data, Vec::<u8>::new());
    }

    #[test]
    fn test_parse_unsigned_transaction_params_missing_from() {
        let tx_data = json!({
            "to": "0xd46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f07244567",
            "value": "0x9184e72a"
        });

        let params_json = json!([tx_data]);
        let params = create_params(params_json);

        let result = parse_unsigned_transaction_params(params);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Missing required 'from' field"));
    }

    #[test]
    fn test_parse_unsigned_transaction_params_with_data() {
        let tx_data = json!({
            "from": "0x742d35Cc6634C0532925a3b8D0b2f0e8e6F5DaBB",
            "data": "0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b8d0b2f0e8e6f5dabb"
        });

        let params_json = json!([tx_data]);
        let params = create_params(params_json);

        let result = parse_unsigned_transaction_params(params).unwrap();

        let expected_data =
            hex::decode("a9059cbb000000000000000000000000742d35cc6634c0532925a3b8d0b2f0e8e6f5dabb")
                .unwrap();
        assert_eq!(result.data, expected_data);
    }

    #[test]
    fn test_parse_l1_to_l2_message_params_single_message() {
        let message = json!({
            "from_address": "0x8453FC6Cd1bCfE8D4dFC069C400B433054d47bDc",
            "l2_address": "0x04c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f",
            "selector": "0x02d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
            "payload": [
                "0x0000000000000000000000008453FC6Cd1bCfE8D4dFC069C400B433054d47bDc",
                "0x00000000000000000000000000000000000000000000000000000000000003e8"
            ]
        });

        let params_json = json!({
            "messages": [message]
        });
        let params = create_params(params_json);

        let result = parse_l1_to_l2_message_params(params).unwrap();

        assert_eq!(result.len(), 1);

        let event = &result[0];
        assert_eq!(
            event.from_address,
            EthAddress::from_hex("0x8453FC6Cd1bCfE8D4dFC069C400B433054d47bDc").unwrap()
        );
        assert_eq!(
            event.l2_address,
            Felt::from_hex("0x04c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f")
                .unwrap()
        );
        assert_eq!(
            event.selector,
            Felt::from_hex("0x02d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5")
                .unwrap()
        );
        assert_eq!(event.payload.len(), 2);
    }

    #[test]
    fn test_parse_l1_to_l2_message_params_multiple_messages() {
        let message1 = json!({
            "from_address": "0x8453FC6Cd1bCfE8D4dFC069C400B433054d47bDc",
            "l2_address": "0x04c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f",
            "selector": "0x02d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
            "payload": ["0x123"]
        });

        let message2 = json!({
            "from_address": "0x742d35Cc6634C0532925a3b8D0b2f0e8e6F5DaBB",
            "l2_address": "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
            "selector": "0x0083afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e",
            "payload": ["0x456", "0x789"]
        });

        let params_json = json!({
            "messages": [message1, message2]
        });
        let params = create_params(params_json);

        let result = parse_l1_to_l2_message_params(params).unwrap();

        assert_eq!(result.len(), 2);

        // Check first message
        let event1 = &result[0];
        assert_eq!(
            event1.from_address,
            EthAddress::from_hex("0x8453FC6Cd1bCfE8D4dFC069C400B433054d47bDc").unwrap()
        );
        assert_eq!(event1.payload.len(), 1);

        // Check second message
        let event2 = &result[1];
        assert_eq!(
            event2.from_address,
            EthAddress::from_hex("0x742d35Cc6634C0532925a3b8D0b2f0e8e6F5DaBB").unwrap()
        );
        assert_eq!(event2.payload.len(), 2);
    }

    #[test]
    fn test_parse_l1_to_l2_message_params_missing_field() {
        let message = json!({
            "from_address": "0x8453FC6Cd1bCfE8D4dFC069C400B433054d47bDc",
            // Missing l2_address
            "selector": "0x02d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
            "payload": ["0x123"]
        });

        let params_json = json!({
            "messages": [message]
        });
        let params = create_params(params_json);

        let result = parse_l1_to_l2_message_params(params);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Missing 'l2_address'"));
    }

    #[test]
    fn test_parse_l1_to_l2_message_params_invalid_address() {
        let message = json!({
            "from_address": "0xinvalid",
            "l2_address": "0x04c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f",
            "selector": "0x02d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
            "payload": ["0x123"]
        });

        let params_json = json!({
            "messages": [message]
        });
        let params = create_params(params_json);

        let result = parse_l1_to_l2_message_params(params);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid from_address"));
    }

    #[test]
    fn test_parse_l1_to_l2_message_params_empty_messages() {
        let params_json = json!({
            "messages": []
        });
        let params = create_params(params_json);

        let result = parse_l1_to_l2_message_params(params).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_l1_to_l2_message_params_missing_messages_array() {
        let params_json = json!({
            "not_messages": []
        });
        let params = create_params(params_json);

        let result = parse_l1_to_l2_message_params(params);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Expected 'messages' array"));
    }

    #[test]
    fn test_parse_params_as_object_not_array() {
        // Test unsigned transaction params as object instead of array
        let tx_data = json!({
            "from": "0x742d35Cc6634C0532925a3b8D0b2f0e8e6F5DaBB",
            "value": "0x123"
        });

        let params = create_params(tx_data);

        let result = parse_unsigned_transaction_params(params).unwrap();
        assert_eq!(result.from, "0x742d35Cc6634C0532925a3b8D0b2f0e8e6F5DaBB");
        assert_eq!(result.value, "0x123");
    }

    #[test]
    fn test_parse_l1_to_l2_message_params_invalid_payload() {
        let message = json!({
            "from_address": "0x8453FC6Cd1bCfE8D4dFC069C400B433054d47bDc",
            "l2_address": "0x04c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f",
            "selector": "0x02d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
            "payload": [123] // Invalid: should be string
        });

        let params_json = json!({
            "messages": [message]
        });
        let params = create_params(params_json);

        let result = parse_l1_to_l2_message_params(params);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected string"));
    }
}
