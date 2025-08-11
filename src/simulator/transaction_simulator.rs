use eyre::{eyre, Report as ErrReport, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

use alloy::{
    consensus::TxEnvelope,
    eips::Encodable2718,
    node_bindings::Anvil,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    sol,
};

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
    // Configuration and state will be added here
    network_config: NetworkConfig,
}

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    ERC20Example,
    "./src/test_utils/ERC20Example.json"
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferEvent {
    pub token_address: Address,
    pub from: Address,
    pub to: Address,
    pub value: U256,
}

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

// Test helper function that returns receipt for event inspection
#[allow(dead_code)]
async fn simulate_tx_with_receipt(
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

#[allow(dead_code)]
fn print_transaction_events(receipt: &alloy::rpc::types::TransactionReceipt) {
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
    pub l2_rpc_url: String,
    pub block_number: Option<u64>,
}

impl TransactionSimulator {
    /// Create a new transaction simulator with the given configuration
    pub fn new(network_config: NetworkConfig) -> Result<Self> {
        info!(
            "Creating new TransactionSimulator with config: {:?}",
            network_config
        );

        // TODO: Validate network configuration
        // TODO: Initialize RPC clients
        // TODO: Set up simulation environment

        Ok(Self { network_config })
    }

    /// Simulate a transaction and return the result
    pub async fn simulate_transaction(
        &self,
        transaction: TransactionData,
    ) -> Result<SimulationResult> {
        info!("Starting transaction simulation for tx: {:?}", transaction);

        // TODO: Implement actual simulation logic
        // This is a placeholder implementation

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

        // TODO: Implement actual fee estimation logic
        // This is a placeholder implementation

        let simulation_result = self.simulate_transaction(transaction).await?;

        // For now, return a placeholder gas estimate
        let estimated_gas = simulation_result.gas_used;

        info!("Estimated gas: {}", estimated_gas);
        Ok(estimated_gas)
    }

    /// Validate transaction data before simulation
    fn validate_transaction(&self, transaction: &TransactionData) -> Result<()> {
        // TODO: Implement comprehensive validation
        // - Check address formats
        // - Validate gas limits
        // - Check value amounts
        // - Validate nonce

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

        // TODO: Add more validation rules

        Ok(())
    }

    /// Execute the actual simulation
    async fn execute_simulation(&self, _transaction: TransactionData) -> Result<SimulationResult> {
        // TODO: Implement the core simulation logic
        // This will include:
        // - Setting up simulation environment
        // - Executing transaction against state
        // - Collecting gas usage, events, state changes
        // - Handling errors and reverts

        warn!("Simulation logic not yet implemented - returning placeholder result");

        // Placeholder result
        Ok(SimulationResult {
            success: true,
            gas_used: 21000, // Default gas for simple transfer
            return_data: vec![],
            events: vec![],
            state_changes: HashMap::new(),
            error_message: None,
        })
    }

    /// Get current network configuration
    pub fn get_network_config(&self) -> &NetworkConfig {
        &self.network_config
    }

    /// Update network configuration
    pub fn update_network_config(&mut self, config: NetworkConfig) -> Result<()> {
        info!("Updating network configuration: {:?}", config);

        // TODO: Validate new configuration
        // TODO: Reconnect to new networks if needed

        self.network_config = config;
        Ok(())
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            l1_rpc_url: "http://localhost:8545".to_string(),
            l2_rpc_url: "http://localhost:5050".to_string(),
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
        primitives::{hex, utils::parse_ether, TxKind, b256, address, Signature},
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
            chain_id: chain_id,
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

        // Use the same Anvil endpoint URL for forking in simulate_tx
        let rpc_url = anvil.endpoint_url();

        // Test the simulate_tx function
        let gas_used = simulate_tx(rpc_url.as_str(), &funding_tx_envelope)
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
        contract_data.extend_from_slice(&bob.as_slice()); // bob's address (20 bytes)

        // U256 parameter (32 bytes): amount in big-endian format
        contract_data.extend_from_slice(&transfer_amount.to_be_bytes::<32>()); // amount

        let mut contract_tx = TxEip1559 {
            chain_id: chain_id,
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

        // Test the simulate_tx function with contract interaction
        let (gas_used, receipt) = simulate_tx_with_receipt(rpc_url.as_str(), &contract_tx_envelope)
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

        let chain_id = provider.get_chain_id().await.unwrap();
        let block_number = provider.get_block_number().await.unwrap();
        println!("Block number: {}", block_number);

        // tx to simulate https://etherscan.io/tx/0xd5fdee26751ba7175444cb587c1b1ddeca3a0d22cbf87bf0c1d6b4d263c6a699

        let mut contract_tx = TxEip1559 {
            chain_id: 1,
            nonce: 58,
            gas_limit: 190_674 , 
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

        // Test the simulate_tx function with contract interaction
        let (gas_used, receipt) = simulate_tx_with_receipt(rpc_url.as_str(), &contract_tx_envelope)
            .await
            .unwrap();

        // Print all events emitted by the transaction
        print_transaction_events(&receipt);

    }
}
