use eyre::{eyre, Report as ErrReport, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use tracing::info;

use alloy::{
    consensus::TxEnvelope,
    eips::Encodable2718,
    node_bindings::Anvil,
    primitives::U256,
    providers::{Provider, ProviderBuilder},
    sol,
    sol_types::SolEvent,
};

use starknet::core::types::{EthAddress, Felt};

/// Represents the result of a transaction simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub success: bool,
    pub gas_used: u64,
    pub return_data: Vec<u8>,
    pub events: Vec<SimulationEvent>,
    pub state_changes: HashMap<String, String>,
    pub error_message: Option<String>,
}

/// Represents an event emitted during simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationEvent {
    pub address: String,
    pub topics: Vec<String>,
    pub data: Vec<u8>,
}

// SimulationError removed - using eyre::Result throughout

/// Transaction data structure for simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionData {
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub data: Vec<u8>,
    pub gas_limit: u64,
    pub gas_price: String,
    pub nonce: u64,
}

/// Main transaction simulator struct
#[derive(Debug)]
pub struct TransactionSimulator {
    network_config: NetworkConfig,
}

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ERC20Example,
    "src/test_utils/ERC20Example.json"
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    StarknetCore,
    "src/simulator/interfaces/StarknetCore.json"
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L1ToL2MessageSentEvent {
    pub from_address: EthAddress,
    pub l2_address: Felt,
    pub selector: Felt,
    pub payload: Vec<Felt>,
}

/// Simulate a transaction using Anvil and return gas used
pub async fn simulate_tx(rpc_url: &str, target_tx: &TxEnvelope) -> Result<u64, ErrReport> {
    let anvil = Anvil::new()
        .arg("--fork-url")
        .arg(rpc_url)
        .try_spawn()
        .unwrap();
    let forked_provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());

    // Encode the TxEnvelope to raw bytes and send as raw transaction
    let raw_tx = target_tx.encoded_2718();
    let pending = forked_provider.send_raw_transaction(&raw_tx).await?;
    let receipt = pending.get_receipt().await?;
    let gas_used = receipt.gas_used;
    Ok(gas_used)
}

/// Simulate a transaction and return both gas used and receipt for event inspection
pub async fn simulate_tx_with_receipt(
    rpc_url: &str,
    target_tx: &TxEnvelope,
) -> Result<(u64, alloy::rpc::types::TransactionReceipt), ErrReport> {
    let anvil = Anvil::new()
        .arg("--fork-url")
        .arg(rpc_url)
        .try_spawn()
        .unwrap();
    let forked_provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());

    // Encode the TxEnvelope to raw bytes and send as raw transaction
    let raw_tx = target_tx.encoded_2718();
    let pending = forked_provider.send_raw_transaction(&raw_tx).await?;
    let receipt = pending.get_receipt().await?;
    let gas_used = receipt.gas_used;
    Ok((gas_used, receipt))
}

fn parse_starknet_l1_to_l2_message_sent_events(
    receipt: &alloy::rpc::types::TransactionReceipt,
) -> Result<Vec<L1ToL2MessageSentEvent>> {
    let decoded_events: Vec<L1ToL2MessageSentEvent> = receipt
        .logs()
        .iter()
        .filter_map(|log| StarknetCore::LogMessageToL2::decode_log(log.as_ref()).ok())
        .map(|l1_to_l2_log| L1ToL2MessageSentEvent {
            from_address: EthAddress::from_str(&l1_to_l2_log.fromAddress.to_string()).unwrap(),
            l2_address: Felt::from_str(&l1_to_l2_log.toAddress.to_string()).unwrap(),
            selector: Felt::from_str(&l1_to_l2_log.selector.to_string()).unwrap(),
            payload: l1_to_l2_log
                .payload
                .iter()
                .map(|felt| Felt::from_str(&felt.to_string()).unwrap())
                .collect(),
        })
        .collect();

    if decoded_events.is_empty() {
        eyre::bail!("No L1 to L2 message sent events found");
    }

    Ok(decoded_events)
}

/// Print detailed transaction events from a receipt (useful for debugging)
pub fn print_transaction_events(receipt: &alloy::rpc::types::TransactionReceipt) {
    println!("Transaction Events:");
    println!("==================");
    let logs = receipt.logs();
    if logs.is_empty() {
        println!("No events emitted");
    } else {
        for (i, log) in logs.iter().enumerate() {
            println!("Event {}:", i + 1);
            println!("  Address: {}", log.address());
            println!("  Topics: {:?}", log.topics());
            println!("  Data: {:?}", log.data());
            println!("  Block Number: {}", log.block_number.unwrap_or(0));
            println!(
                "  Transaction Hash: {}",
                log.transaction_hash.unwrap_or_default()
            );
            println!("  Log Index: {}", log.log_index.unwrap_or(0));
            println!(
                "  Transaction Index: {}",
                log.transaction_index.unwrap_or(0)
            );
            println!("  Removed: {}", log.removed);
            println!("---");
        }
    }
    println!("==================");
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub l1_rpc_url: String,
    pub block_number: Option<u64>,
}

impl TransactionSimulator {
    /// Create a new transaction simulator with the given configuration
    pub fn new(network_config: NetworkConfig) -> Result<Self> {
        info!(
            "Creating new TransactionSimulator with config: {:?}",
            network_config
        );

        // Validate network configuration
        if network_config.l1_rpc_url.is_empty() {
            return Err(eyre!("L1 RPC URL cannot be empty"));
        }

        Ok(Self { network_config })
    }

    /// Simulate a transaction envelope using the L1 RPC
    pub async fn simulate_tx_envelope(&self, target_tx: &TxEnvelope) -> Result<u64> {
        info!("Simulating transaction envelope");
        simulate_tx(&self.network_config.l1_rpc_url, target_tx).await
    }

    /// Simulate a transaction envelope and return both gas used and receipt
    pub async fn simulate_tx_envelope_with_receipt(
        &self,
        target_tx: &TxEnvelope,
    ) -> Result<(u64, alloy::rpc::types::TransactionReceipt)> {
        info!("Simulating transaction envelope with receipt");
        simulate_tx_with_receipt(&self.network_config.l1_rpc_url, target_tx).await
    }

    /// Parse Starknet L1 to L2 message events from a transaction receipt
    pub fn parse_l1_to_l2_message_events(
        &self,
        receipt: &alloy::rpc::types::TransactionReceipt,
    ) -> Result<Vec<L1ToL2MessageSentEvent>> {
        parse_starknet_l1_to_l2_message_sent_events(receipt)
    }

    /// Simulate a transaction and return the result
    pub async fn simulate_transaction(
        &self,
        transaction: TransactionData,
    ) -> Result<SimulationResult> {
        info!("Starting transaction simulation for tx: {:?}", transaction);

        // Validate transaction data
        self.validate_transaction(&transaction)?;

        // Perform simulation
        let result = self.execute_simulation(transaction).await?;

        info!("Simulation completed with result: {:?}", result);
        Ok(result)
    }

    /// Estimate gas fee for a transaction
    pub async fn estimate_fee(&self, transaction: TransactionData) -> Result<u64> {
        info!("Estimating fee for transaction: {:?}", transaction);

        let simulation_result = self.simulate_transaction(transaction).await?;
        let estimated_gas = simulation_result.gas_used;

        info!("Estimated gas: {}", estimated_gas);
        Ok(estimated_gas)
    }

    /// Validate transaction data before simulation
    fn validate_transaction(&self, transaction: &TransactionData) -> Result<()> {
        if transaction.from.is_empty() {
            return Err(eyre!(
                "Invalid transaction data: From address cannot be empty"
            ));
        }

        if transaction.gas_limit == 0 {
            return Err(eyre!(
                "Invalid transaction data: Gas limit must be greater than 0"
            ));
        }

        // Validate address format for 'from' field
        if !transaction.from.starts_with("0x") || transaction.from.len() != 42 {
            return Err(eyre!("Invalid from address format: {}", transaction.from));
        }

        // Validate 'to' address if present
        if let Some(to) = &transaction.to {
            if !to.starts_with("0x") || to.len() != 42 {
                return Err(eyre!("Invalid to address format: {}", to));
            }
        }

        Ok(())
    }

    /// Execute the actual simulation
    async fn execute_simulation(&self, transaction: TransactionData) -> Result<SimulationResult> {
        // For now, this is a simplified implementation that returns estimated values
        // In a full implementation, this would use the Anvil simulation infrastructure
        // to execute the transaction and collect detailed results

        // Basic gas estimation based on transaction type
        let base_gas = 21000u64; // Base transaction cost
        let data_gas = transaction.data.len() as u64 * 16; // Rough data cost estimation
        let estimated_gas = base_gas + data_gas;

        info!(
            "Executing simulation for transaction with estimated gas: {}",
            estimated_gas
        );

        Ok(SimulationResult {
            success: true,
            gas_used: estimated_gas,
            return_data: vec![],
            events: vec![],
            state_changes: HashMap::new(),
            error_message: None,
        })
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            l1_rpc_url: "http://localhost:8545".to_string(),
            block_number: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        consensus::TxEip1559,
        eips::eip2930::AccessList,
        eips::{eip1559::BaseFeeParams, BlockId},
        network::TxSignerSync,
        primitives::{address, b256, hex, utils::parse_ether, Signature, TxKind},
        signers::local::PrivateKeySigner,
    };

    #[tokio::test]
    async fn test_simulator_creation() {
        let config = NetworkConfig::default();
        let simulator = TransactionSimulator::new(config);
        assert!(simulator.is_ok());
    }

    #[tokio::test]
    async fn test_transaction_validation() {
        let config = NetworkConfig::default();
        let simulator = TransactionSimulator::new(config).unwrap();

        let invalid_tx = TransactionData {
            from: "".to_string(), // Invalid empty from address
            to: None,
            value: "0".to_string(),
            data: vec![],
            gas_limit: 21000,
            gas_price: "20000000000".to_string(),
            nonce: 0,
        };

        let result = simulator.validate_transaction(&invalid_tx);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_simulate_tx() {
        // Spawn Anvil and get its endpoint URL
        let anvil = Anvil::new().try_spawn().unwrap();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
        let accounts = provider.get_accounts().await.unwrap();
        let alice = accounts[0];
        let bob = accounts[1];

        let chain_id = provider.get_chain_id().await.unwrap();
        let transfer_value = parse_ether("0.1").unwrap();

        // Get current block for base fee calculation
        let block = provider
            .get_block(BlockId::latest())
            .await
            .unwrap()
            .unwrap();
        let base_fee = U256::from(
            block
                .header
                .next_block_base_fee(BaseFeeParams::ethereum())
                .unwrap(),
        );
        let one_gwei = U256::from(1_000_000_000u64);
        let fee = base_fee + one_gwei;
        let fee_u128 = fee.as_limbs()[0] as u128;
        let one_gwei_u128 = one_gwei.as_limbs()[0] as u128;

        // Create transaction from Alice to Bob
        let alice_nonce = provider.get_transaction_count(alice).await.unwrap();

        let mut funding_tx = TxEip1559 {
            chain_id,
            nonce: alice_nonce,
            gas_limit: 21000,
            max_fee_per_gas: fee_u128,
            max_priority_fee_per_gas: one_gwei_u128,
            input: hex!("0x").into(),
            to: TxKind::Call(bob),
            value: transfer_value,
            access_list: AccessList::default(),
        };

        // Get Alice's private key from Anvil (first account)
        let alice_private_key = anvil.keys()[0].clone();
        let alice_signer = PrivateKeySigner::from(alice_private_key);
        let signature = alice_signer.sign_transaction_sync(&mut funding_tx).unwrap();

        let funding_tx_envelope = TxEnvelope::new_unhashed(funding_tx.into(), signature);

        // Create a TransactionSimulator with the Anvil endpoint
        let config = NetworkConfig {
            l1_rpc_url: anvil.endpoint_url().to_string(),
            block_number: None,
        };
        let simulator = TransactionSimulator::new(config).unwrap();

        // Test the simulate_tx_envelope method
        let gas_used = simulator
            .simulate_tx_envelope(&funding_tx_envelope)
            .await
            .unwrap();

        // Verify that gas was used (should be around 21000 for a simple transfer)
        assert!(gas_used > 0, "Gas used should be greater than 0");
        assert!(gas_used <= 21000, "Gas used should not exceed gas limit");

        println!("Simulated transaction gas used: {}", gas_used);
    }

    #[tokio::test]
    async fn test_simulate_tx_with_contract_interaction() {
        // Spawn Anvil and get its endpoint URL
        let anvil = Anvil::new().try_spawn().unwrap();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
        let accounts = provider.get_accounts().await.unwrap();
        let alice = accounts[0];
        let bob = accounts[1];

        // Get Alice's private key and create signer once
        let alice_private_key = anvil.keys()[0].clone();
        let alice_signer = PrivateKeySigner::from(alice_private_key);

        // Deploy the ERC20 token from Alice's account
        let alice_provider = ProviderBuilder::new()
            .wallet(alice_signer.clone())
            .connect_provider(provider.clone());
        let erc20_contract = ERC20Example::deploy(&alice_provider).await.unwrap();
        let token_address = erc20_contract.address();

        let chain_id = provider.get_chain_id().await.unwrap();

        // Get current block for base fee calculation
        let block = provider
            .get_block(BlockId::latest())
            .await
            .unwrap()
            .unwrap();
        let base_fee = U256::from(
            block
                .header
                .next_block_base_fee(BaseFeeParams::ethereum())
                .unwrap(),
        );
        let one_gwei = U256::from(1_000_000_000u64);
        let fee = base_fee + one_gwei;
        let fee_u128 = fee.as_limbs()[0] as u128;
        let one_gwei_u128 = one_gwei.as_limbs()[0] as u128;

        // Create a transaction to transfer ERC20 tokens
        let alice_nonce = provider.get_transaction_count(alice).await.unwrap();

        // ERC20 transfer function call data
        // transfer(address to, uint256 amount) -> 0xa9059cbb
        // to: bob address (padded to 32 bytes)
        // amount: 1000 (padded to 32 bytes)
        let transfer_amount = U256::from(1000u64);
        let mut contract_data = vec![0xa9, 0x05, 0x9c, 0xbb]; // transfer function selector

        // Address parameter (32 bytes): 12 bytes padding + 20 bytes address
        contract_data.extend_from_slice(&[0u8; 12]); // padding for address
        contract_data.extend_from_slice(bob.as_slice()); // bob's address (20 bytes)

        // U256 parameter (32 bytes): amount in big-endian format
        contract_data.extend_from_slice(&transfer_amount.to_be_bytes::<32>()); // amount

        let mut contract_tx = TxEip1559 {
            chain_id,
            nonce: alice_nonce,
            gas_limit: 100000, // Higher gas limit for contract interaction
            max_fee_per_gas: fee_u128,
            max_priority_fee_per_gas: one_gwei_u128,
            input: contract_data.into(),
            to: TxKind::Call(*token_address),
            value: U256::ZERO, // No ETH transfer, just contract call
            access_list: AccessList::default(),
        };

        // Use the same signer for transaction signing
        let signature = alice_signer
            .sign_transaction_sync(&mut contract_tx)
            .unwrap();

        let contract_tx_envelope = TxEnvelope::new_unhashed(contract_tx.into(), signature);

        // Use the same Anvil endpoint URL for forking in simulate_tx
        let rpc_url = anvil.endpoint_url();

        // Create a TransactionSimulator with the Anvil endpoint
        let config = NetworkConfig {
            l1_rpc_url: rpc_url.to_string(),

            block_number: None,
        };
        let simulator = TransactionSimulator::new(config).unwrap();

        // Test the simulate_tx_envelope_with_receipt method
        let (gas_used, receipt) = simulator
            .simulate_tx_envelope_with_receipt(&contract_tx_envelope)
            .await
            .unwrap();

        // Print all events emitted by the transaction
        print_transaction_events(&receipt);

        // Parse and display ERC20 transfer events
        // Verify that gas was used (should be higher than simple transfer)
        assert!(gas_used > 0, "Gas used should be greater than 0");
        assert!(gas_used <= 100000, "Gas used should not exceed gas limit");

        println!("Simulated contract transaction gas used: {}", gas_used);
    }

    #[tokio::test]
    async fn test_starknet_deposit_tx() {
        // Spawn Anvil and get its endpoint URL
        let anvil = Anvil::new()
            .arg("--fork-url")
            .arg("https://reth-ethereum.ithaca.xyz/rpc")
            .fork_block_number(23113921)
            .try_spawn()
            .unwrap();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());

        let _chain_id = provider.get_chain_id().await.unwrap();
        let block_number = provider.get_block_number().await.unwrap();
        println!("Block number: {}", block_number);

        // tx to simulate https://etherscan.io/tx/0xd5fdee26751ba7175444cb587c1b1ddeca3a0d22cbf87bf0c1d6b4d263c6a699

        let contract_tx = TxEip1559 {
            chain_id: 1,
            nonce: 58,
            gas_limit: 190_674,
            max_fee_per_gas: 2306574200,
            max_priority_fee_per_gas: 2000000000,
            input: hex!("0x0efe6a8b000000000000000000000000ca14007eff0db1f8135f4c25b34de49ab0d42766000000000000000000000000000000000000000000004f9c6a3ec958b0de0000013cd2f10b45da0332429cea44028b89ee386cb2adfb9bb8f1c470bad6a1f8d1").into(),
            to: TxKind::Call(address!("0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4")),
            value: U256::from(25344429452040_u128),
            access_list: AccessList::default(),
        };

        let signature = Signature::from_scalars_and_parity(
            b256!("60fc7c691cba78738fef6bcf264f5ff8b896ed3e6c885d2f171bf0658a07d307"),
            b256!("1040aa1cf5035f0a6f757f79c9defba2819a9626a472b37d45ce5ceb9e4a0af9"),
            true,
        );

        let contract_tx_envelope = TxEnvelope::new_unhashed(contract_tx.into(), signature);

        // Use the same Anvil endpoint URL for forking in simulate_tx
        let rpc_url = anvil.endpoint_url();

        // Create a TransactionSimulator with the Anvil endpoint
        let config = NetworkConfig {
            l1_rpc_url: rpc_url.to_string(),

            block_number: None,
        };
        let simulator = TransactionSimulator::new(config).unwrap();

        // Test the simulate_tx_envelope_with_receipt method
        let (_gas_used, receipt) = simulator
            .simulate_tx_envelope_with_receipt(&contract_tx_envelope)
            .await
            .unwrap();

        // Print all events emitted by the transaction
        print_transaction_events(&receipt);

        let l1_to_l2_logs = simulator.parse_l1_to_l2_message_events(&receipt).unwrap();
        println!(
            "Found {} L1 to L2 message sent events:",
            l1_to_l2_logs.len()
        );
        for (i, log) in l1_to_l2_logs.iter().enumerate() {
            println!("  Event {}:", i + 1);
            println!("    from_address: {:?}", log.from_address);
            println!("    to_address: {}", log.l2_address);
            println!("    selector: {}", log.selector);
            println!("    payload: {:?}", log.payload);
        }

        // Assertions for the test
        // This specific transaction should emit exactly 1 L1ToL2MessageSent event
        assert_eq!(
            l1_to_l2_logs.len(),
            1,
            "Expected exactly 1 L1ToL2MessageSent event, but found {}",
            l1_to_l2_logs.len()
        );

        let event = &l1_to_l2_logs[0];

        let expected_from_address =
            EthAddress::from_str("0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4").unwrap();

        // Expected values based on the actual decoded event output
        // to_address: Convert from decimal output we see: 2524392021852001135582825949054576525094493216367559068627275826195272239197
        let expected_to_address = Felt::from_str(
            "2524392021852001135582825949054576525094493216367559068627275826195272239197",
        )
        .unwrap();
        // selector: Convert from decimal output we see: 774397379524139446221206168840917193112228400237242521560346153613428128537
        let expected_selector = Felt::from_str(
            "774397379524139446221206168840917193112228400237242521560346153613428128537",
        )
        .unwrap();

        assert_eq!(event.from_address, expected_from_address);

        // Assert the to_address matches expected value
        assert_eq!(
            event.l2_address, expected_to_address,
            "L2 address mismatch. Expected: {}, Got: {}",
            expected_to_address, event.l2_address
        );

        // Assert the selector matches expected value
        assert_eq!(
            event.selector, expected_selector,
            "Selector mismatch. Expected: {}, Got: {}",
            expected_selector, event.selector
        );

        // Assert that payload is not empty and has expected structure
        assert!(
            !event.payload.is_empty(),
            "Expected non-empty payload, but payload was empty"
        );

        // The payload should contain exactly 5 elements based on the output
        assert_eq!(
            event.payload.len(),
            5,
            "Expected payload to have 5 elements, but found {}",
            event.payload.len()
        );

        // Assert specific payload values from the decoded output
        let expected_payload = vec![
            Felt::from_str("0xca14007eff0db1f8135f4c25b34de49ab0d42766").unwrap(), // First payload element
            Felt::from_str("0x11dd734a52cd2ee23ffe8b5054f5a8ecf5d1ad50").unwrap(), // Second payload element
            Felt::from_str("0x13cd2f10b45da0332429cea44028b89ee386cb2adfb9bb8f1c470bad6a1f8d1")
                .unwrap(), // Third payload element
            Felt::from_str("0x4f9c6a3ec958b0de0000").unwrap(), // Fourth payload element
            Felt::ZERO,                                        // Fifth payload element (0x0)
        ];

        for (i, (actual, expected)) in event
            .payload
            .iter()
            .zip(expected_payload.iter())
            .enumerate()
        {
            assert_eq!(
                actual, expected,
                "Payload element {} mismatch. Expected: {}, Got: {}",
                i, expected, actual
            );
        }
    }

    // TODO: add test with two events

    // TODO: add test with no events
}
