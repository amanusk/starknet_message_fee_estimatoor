use eyre::{eyre, Result};
use log::{error, info};
use serde::{Deserialize, Serialize};
use starknet::core::types::{BlockId, BlockTag, Felt, MsgFromL1};
use starknet::providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider};
use std::sync::Arc;

use crate::simulator::transaction_simulator::L1ToL2MessageSentEvent;

/// Configuration for the Starknet fee estimator
#[derive(Debug, Clone)]
pub struct StarknetFeeEstimatorConfig {
    pub rpc_url: String,
    pub block_id: BlockId,
}

impl Default for StarknetFeeEstimatorConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://pathfinder.rpc.mainnet.starknet.rs/rpc/v0_8".to_string(),
            block_id: BlockId::Tag(BlockTag::Latest),
        }
    }
}

/// Fee estimation result for a single message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageFeeEstimate {
    pub l2_address: Felt,
    pub selector: Felt,
    pub gas_consumed: u64,
    pub gas_price: u128,
    pub overall_fee: u128,
    pub unit: String,
}

/// Summary of fee estimation for multiple messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimationSummary {
    pub total_messages: usize,
    pub successful_estimates: usize,
    pub failed_estimates: usize,
    pub total_fee_wei: u128,
    pub total_fee_eth: f64,
    pub individual_estimates: Vec<MessageFeeEstimate>,
    pub errors: Vec<String>,
}

/// The main Starknet fee estimator
#[derive(Debug)]
pub struct StarknetFeeEstimator {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    config: StarknetFeeEstimatorConfig,
}

impl StarknetFeeEstimator {
    /// Create a new Starknet fee estimator with the given configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the RPC URL is invalid or cannot be parsed
    pub fn new(config: StarknetFeeEstimatorConfig) -> Result<Self> {
        info!("Creating StarknetFeeEstimator with URL: {}", config.rpc_url);

        let transport = HttpTransport::new(
            reqwest::Url::parse(&config.rpc_url)
                .map_err(|e| eyre!("Invalid RPC URL '{}': {}", config.rpc_url, e))?,
        );
        let provider = Arc::new(JsonRpcClient::new(transport));

        Ok(Self { provider, config })
    }

    /// Create a new estimator from a simple RPC URL string
    ///
    /// # Errors
    ///
    /// Returns an error if the RPC URL is invalid or cannot be parsed
    pub fn from_url(rpc_url: &str) -> Result<Self> {
        let config = StarknetFeeEstimatorConfig {
            rpc_url: rpc_url.to_string(),
            ..Default::default()
        };
        Self::new(config)
    }

    /// Estimate fees for a single L1 to L2 message
    ///
    /// # Errors
    ///
    /// Returns an error if the fee estimation fails due to network issues or invalid message data
    pub async fn estimate_single_message_fee(
        &self,
        event: &L1ToL2MessageSentEvent,
    ) -> Result<MessageFeeEstimate> {
        info!(
            "Estimating fee for message to address: {}",
            event.l2_address
        );

        let message = MsgFromL1 {
            from_address: event.from_address.clone(),
            to_address: event.l2_address,
            entry_point_selector: event.selector,
            payload: event.payload.clone(),
        };

        // Estimate the fee
        let fee_estimate = self
            .provider
            .estimate_message_fee(message, self.config.block_id)
            .await
            .map_err(|e| eyre!("Failed to estimate message fee: {}", e))?;

        Ok(MessageFeeEstimate {
            l2_address: event.l2_address,
            selector: event.selector,
            gas_consumed: fee_estimate.l1_gas_consumed,
            gas_price: fee_estimate.l1_gas_price,
            overall_fee: fee_estimate.overall_fee,
            unit: format!("{:?}", fee_estimate.unit),
        })
    }

    /// Estimate fees for multiple L1 to L2 messages and return a summary
    ///
    /// # Errors
    ///
    /// Returns an error if the fee estimation fails due to network issues or invalid message data
    pub async fn estimate_messages_fee(
        &self,
        events: Vec<L1ToL2MessageSentEvent>,
    ) -> Result<FeeEstimationSummary> {
        let total_messages = events.len();
        info!("Estimating fees for {} L1 to L2 messages", total_messages);

        if events.is_empty() {
            return Ok(FeeEstimationSummary {
                total_messages: 0,
                successful_estimates: 0,
                failed_estimates: 0,
                total_fee_wei: 0,
                total_fee_eth: 0.0,
                individual_estimates: vec![],
                errors: vec![],
            });
        }

        let mut individual_estimates = Vec::new();
        let mut errors = Vec::new();
        let mut total_fee_wei = 0u128;

        for (index, event) in events.iter().enumerate() {
            match self.estimate_single_message_fee(event).await {
                Ok(estimate) => {
                    total_fee_wei = total_fee_wei.saturating_add(estimate.overall_fee);
                    individual_estimates.push(estimate);
                }
                Err(e) => {
                    let error_msg = format!("Message {}: {}", index + 1, e);
                    error!("{}", error_msg);
                    errors.push(error_msg);
                }
            }
        }

        let successful_estimates = individual_estimates.len();
        let failed_estimates = total_messages - successful_estimates;

        // Convert Wei to ETH (1 ETH = 10^18 Wei) - using f64 for precision
        #[allow(clippy::cast_precision_loss)]
        let total_fee_eth = total_fee_wei as f64 / 1_000_000_000_000_000_000.0;

        info!(
            "Fee estimation completed: {}/{} successful, total fee: {} Wei ({:.6} ETH)",
            successful_estimates, total_messages, total_fee_wei, total_fee_eth
        );

        Ok(FeeEstimationSummary {
            total_messages,
            successful_estimates,
            failed_estimates,
            total_fee_wei,
            total_fee_eth,
            individual_estimates,
            errors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::{debug, error, info};
    use starknet::core::types::Felt;

    #[test]
    fn test_fee_estimator_creation() {
        let config = StarknetFeeEstimatorConfig::default();
        let estimator = StarknetFeeEstimator::new(config);
        assert!(estimator.is_ok());
    }

    #[test]
    fn test_fee_estimator_from_url() {
        let estimator =
            StarknetFeeEstimator::from_url("https://pathfinder.rpc.mainnet.starknet.rs/rpc/v0_8");
        assert!(estimator.is_ok());
    }

    #[test]
    fn test_invalid_url() {
        let result = StarknetFeeEstimator::from_url("invalid-url");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_empty_events_list() {
        let estimator =
            StarknetFeeEstimator::from_url("https://pathfinder.rpc.mainnet.starknet.rs/rpc/v0_8")
                .unwrap();
        let result = estimator.estimate_messages_fee(vec![]).await.unwrap();

        assert_eq!(result.total_messages, 0);
        assert_eq!(result.successful_estimates, 0);
        assert_eq!(result.failed_estimates, 0);
        assert_eq!(result.total_fee_wei, 0);
        assert_eq!(result.total_fee_eth, 0.0);
        assert!(result.individual_estimates.is_empty());
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_fee_estimation_summary_creation() {
        let summary = FeeEstimationSummary {
            total_messages: 2,
            successful_estimates: 1,
            failed_estimates: 1,
            total_fee_wei: 1000000000000000000,
            total_fee_eth: 1.0,
            individual_estimates: vec![],
            errors: vec!["Test error".to_string()],
        };

        assert_eq!(summary.total_messages, 2);
        assert_eq!(summary.total_fee_eth, 1.0);
        assert_eq!(summary.errors.len(), 1);
    }

    #[tokio::test]
    async fn test_single_message_fee_estimation() {
        use starknet::core::types::{EthAddress, Felt};
        use std::str::FromStr;

        // Create fee estimator with Starknet mainnet endpoint
        let estimator =
            StarknetFeeEstimator::from_url("https://pathfinder.rpc.mainnet.starknet.rs/rpc/v0_8")
                .unwrap();

        // Create a test message using values from the actual Starknet deposit transaction
        // These values are extracted from the test_starknet_deposit_tx test in transaction_simulator.rs
        let test_event = L1ToL2MessageSentEvent {
            from_address: EthAddress::from_str("0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4")
                .unwrap(),
            l2_address: Felt::from_str(
                "2524392021852001135582825949054576525094493216367559068627275826195272239197",
            )
            .unwrap(),
            selector: Felt::from_str(
                "774397379524139446221206168840917193112228400237242521560346153613428128537",
            )
            .unwrap(),
            payload: vec![
                Felt::from_str("0xca14007eff0db1f8135f4c25b34de49ab0d42766").unwrap(), // First payload element
                Felt::from_str("0x11dd734a52cd2ee23ffe8b5054f5a8ecf5d1ad50").unwrap(), // Second payload element
                Felt::from_str("0x13cd2f10b45da0332429cea44028b89ee386cb2adfb9bb8f1c470bad6a1f8d1")
                    .unwrap(), // Third payload element
                Felt::from_str("0x4f9c6a3ec958b0de0000").unwrap(), // Fourth payload element
                Felt::ZERO,                                        // Fifth payload element (0x0)
            ],
        };

        // Estimate fee for the single message
        let result = estimator.estimate_single_message_fee(&test_event).await;

        // Assert that the result is Ok
        assert!(result.is_ok(), "Fee estimation should succeed");

        let estimate = result.unwrap();

        // Verify that the estimate contains correct values
        assert_eq!(estimate.l2_address, test_event.l2_address);
        assert_eq!(estimate.selector, test_event.selector);
        assert!(estimate.gas_consumed > 0);
        assert!(estimate.gas_price > 0);
        assert!(estimate.overall_fee > 0);
        assert!(!estimate.unit.is_empty());
    }

    #[tokio::test]
    async fn test_double_deposit_fee_estimation() {
        use starknet::core::types::{EthAddress, Felt};
        use std::str::FromStr;

        // Create fee estimator with Starknet mainnet endpoint
        let estimator =
            StarknetFeeEstimator::from_url("https://pathfinder.rpc.mainnet.starknet.rs/rpc/v0_8")
                .unwrap();

        // Create the first test message using values from the actual Starknet deposit transaction
        // These values are extracted from the test_starknet_deposit_tx test in transaction_simulator.rs
        let test_event_1 = L1ToL2MessageSentEvent {
            from_address: EthAddress::from_str("0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4")
                .unwrap(),
            l2_address: Felt::from_str(
                "2524392021852001135582825949054576525094493216367559068627275826195272239197",
            )
            .unwrap(),
            selector: Felt::from_str(
                "774397379524139446221206168840917193112228400237242521560346153613428128537",
            )
            .unwrap(),
            payload: vec![
                Felt::from_str("0xca14007eff0db1f8135f4c25b34de49ab0d42766").unwrap(), // First payload element
                Felt::from_str("0x11dd734a52cd2ee23ffe8b5054f5a8ecf5d1ad50").unwrap(), // Second payload element
                Felt::from_str("0x13cd2f10b45da0332429cea44028b89ee386cb2adfb9bb8f1c470bad6a1f8d1")
                    .unwrap(), // Third payload element
                Felt::from_str("0x4f9c6a3ec958b0de0000").unwrap(), // Fourth payload element
                Felt::ZERO,                                        // Fifth payload element (0x0)
            ],
        };

        // Create a second test message with same recipient but different amount
        // This simulates a second deposit transaction to the same recipient with different amount
        let test_event_2 = L1ToL2MessageSentEvent {
            from_address: EthAddress::from_str("0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4")
                .unwrap(),
            l2_address: Felt::from_str(
                "2524392021852001135582825949054576525094493216367559068627275826195272239197",
            )
            .unwrap(),
            selector: Felt::from_str(
                "774397379524139446221206168840917193112228400237242521560346153613428128537",
            )
            .unwrap(),
            payload: vec![
                Felt::from_str("0xca14007eff0db1f8135f4c25b34de49ab0d42766").unwrap(), // Same recipient address
                Felt::from_str("0x11dd734a52cd2ee23ffe8b5054f5a8ecf5d1ad50").unwrap(), // Same second payload (token address)
                Felt::from_str("0x13cd2f10b45da0332429cea44028b89ee386cb2adfb9bb8f1c470bad6a1f8d1")
                    .unwrap(), // Same third payload element
                Felt::from_str("0x2386f26fc10000").unwrap(), // Different amount (smaller)
                Felt::ZERO,                                  // Fifth payload element (0x0)
            ],
        };

        // Create array of two events for double deposit estimation
        let events = vec![test_event_1.clone(), test_event_2.clone()];

        // Estimate fees for both messages
        let result = estimator.estimate_messages_fee(events).await;

        // Assert that the result is Ok
        assert!(
            result.is_ok(),
            "Fee estimation should succeed for double deposit"
        );

        let summary = result.unwrap();

        // Log debug information
        info!("Fee estimation summary:");
        info!("  Total messages: {}", summary.total_messages);
        info!("  Successful estimates: {}", summary.successful_estimates);
        info!("  Failed estimates: {}", summary.failed_estimates);
        info!(
            "  Total fee: {} Wei ({:.6} ETH)",
            summary.total_fee_wei, summary.total_fee_eth
        );
        info!(
            "  Individual estimates count: {}",
            summary.individual_estimates.len()
        );
        debug!("  Errors: {:?}", summary.errors);

        // Verify summary metrics
        assert_eq!(summary.total_messages, 2, "Should have 2 total messages");

        // If there are errors, log them and handle accordingly
        if !summary.errors.is_empty() {
            error!("Errors encountered:");
            for error in &summary.errors {
                error!("  - {}", error);
            }
        }

        // Both estimates should succeed now that we're using valid payload data
        assert_eq!(
            summary.successful_estimates, 2,
            "Both estimates should succeed"
        );
        assert_eq!(summary.failed_estimates, 0, "No estimates should fail");
        assert!(
            summary.total_fee_wei > 0,
            "Total fee should be greater than 0"
        );
        assert!(
            summary.total_fee_eth > 0.0,
            "Total fee in ETH should be greater than 0"
        );
        assert_eq!(
            summary.individual_estimates.len(),
            2,
            "Should have exactly 2 individual estimates"
        );
        assert!(summary.errors.is_empty(), "Should have no errors");

        // Verify individual estimates (both should be available)
        let estimate_1 = &summary.individual_estimates[0];
        let estimate_2 = &summary.individual_estimates[1];

        // Check that both estimates have valid values
        assert_eq!(estimate_1.l2_address, test_event_1.l2_address);
        assert_eq!(estimate_1.selector, test_event_1.selector);
        assert!(estimate_1.gas_consumed > 0);
        assert!(estimate_1.gas_price > 0);
        assert!(estimate_1.overall_fee > 0);

        assert_eq!(estimate_2.l2_address, test_event_2.l2_address);
        assert_eq!(estimate_2.selector, test_event_2.selector);
        assert!(estimate_2.gas_consumed > 0);
        assert!(estimate_2.gas_price > 0);
        assert!(estimate_2.overall_fee > 0);

        info!("Message 1 fee: {} Wei", estimate_1.overall_fee);
        info!("Message 2 fee: {} Wei", estimate_2.overall_fee);

        // Verify that total fee is the sum of individual fees
        let expected_total_fee: u128 = summary
            .individual_estimates
            .iter()
            .map(|est| est.overall_fee)
            .sum();
        assert_eq!(
            summary.total_fee_wei, expected_total_fee,
            "Total fee should equal sum of individual fees"
        );

        // Verify ETH conversion is correct (1 ETH = 10^18 Wei)
        let expected_eth_fee = expected_total_fee as f64 / 1_000_000_000_000_000_000.0;
        assert!(
            (summary.total_fee_eth - expected_eth_fee).abs() < 1e-10,
            "ETH conversion should be accurate"
        );

        info!("Double deposit fee estimation completed successfully:");
        info!(
            "  Total fee: {} Wei ({:.6} ETH)",
            summary.total_fee_wei, summary.total_fee_eth
        );
        info!("  Both estimates succeeded!");
    }

    #[tokio::test]
    async fn test_jsonrpc_estimate_message_fee_sanity_check() {
        use starknet::core::types::EthAddress;
        use starknet::providers::Url;

        let rpc_url = std::env::var("STARKNET_RPC")
            .unwrap_or_else(|_| "https://pathfinder.rpc.sepolia.starknet.rs/rpc/v0_8".into());
        let rpc_client = JsonRpcClient::new(HttpTransport::new(Url::parse(&rpc_url).unwrap()));

        let estimate = rpc_client
            .estimate_message_fee(
                MsgFromL1 {
                    from_address: EthAddress::from_hex(
                        "0x8453FC6Cd1bCfE8D4dFC069C400B433054d47bDc",
                    )
                    .unwrap(),
                    to_address: Felt::from_hex(
                        "04c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f",
                    )
                    .unwrap(),
                    entry_point_selector: Felt::from_hex(
                        "02d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
                    )
                    .unwrap(),
                    payload: vec![Felt::ONE, Felt::ONE, Felt::ONE],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .unwrap();

        debug!("estimate: {:?}", estimate);

        assert!(estimate.l1_gas_consumed > 0);
        assert!(estimate.l1_gas_price > 0);
        assert!(estimate.overall_fee > 0);
    }
}
