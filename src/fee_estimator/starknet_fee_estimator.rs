use eyre::{eyre, Result};
use serde::{Deserialize, Serialize};
use starknet::core::types::{BlockId, BlockTag, EthAddress, Felt, MsgFromL1};
use starknet::providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider};
use std::sync::Arc;
use tracing::{error, info, warn};

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
    pub fn from_url(rpc_url: &str) -> Result<Self> {
        let config = StarknetFeeEstimatorConfig {
            rpc_url: rpc_url.to_string(),
            ..Default::default()
        };
        Self::new(config)
    }

    /// Estimate fees for a single L1 to L2 message
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
            gas_consumed: fee_estimate.l1_gas_consumed.try_into().unwrap_or_else(|_| {
                warn!("Gas consumed value too large, using u64::MAX");
                u64::MAX
            }),
            gas_price: fee_estimate.l1_gas_price.try_into().unwrap_or_else(|_| {
                warn!("Gas price value too large, using u128::MAX");
                u128::MAX
            }),
            overall_fee: fee_estimate.overall_fee.try_into().unwrap_or_else(|_| {
                warn!("Overall fee value too large, using u128::MAX");
                u128::MAX
            }),
            unit: format!("{:?}", fee_estimate.unit),
        })
    }

    /// Estimate fees for multiple L1 to L2 messages and return a summary
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

        // Convert Wei to ETH (1 ETH = 10^18 Wei)
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

    /// Get the current configuration
    pub fn config(&self) -> &StarknetFeeEstimatorConfig {
        &self.config
    }

    /// Update the block ID for future estimates
    pub fn set_block_id(&mut self, block_id: BlockId) {
        self.config.block_id = block_id;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        println!("estimate: {:?}", estimate);

        assert!(estimate.l1_gas_consumed > 0);
        assert!(estimate.l1_gas_price > 0);
        assert!(estimate.overall_fee > 0);
    }
}
