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
            rpc_url: "https://starknet-mainnet.public.blastapi.io".to_string(),
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

        // For L1 to L2 messages, we need to construct a MsgFromL1
        // The from_address is typically the L1 contract address (we'll use a default for now)
        // In a real implementation, this should be passed as a parameter or extracted from the event context
        let from_address = EthAddress::from_hex("0x0000000000000000000000000000000000000000")
            .map_err(|e| eyre!("Invalid default from_address: {}", e))?;

        let message = MsgFromL1 {
            from_address,
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
            StarknetFeeEstimator::from_url("https://starknet-mainnet.public.blastapi.io");
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
            StarknetFeeEstimator::from_url("https://starknet-mainnet.public.blastapi.io").unwrap();
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
}
