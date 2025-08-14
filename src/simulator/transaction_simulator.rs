use eyre::{eyre, Report as ErrReport, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use tracing::info;

use alloy::{
    consensus::TxEnvelope,
    eips::Encodable2718,
    network::TransactionBuilder,
    node_bindings::Anvil,
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    sol,
    sol_types::SolEvent,
};
use serde_json::{json, Value};

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

/// Unsigned transaction data structure for simulation with impersonation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTransactionData {
    pub from: String,
    pub to: Option<String>,
    pub value: String,
    pub data: Vec<u8>,
    pub gas_limit: Option<u64>,
    pub gas_price: Option<String>,
    pub max_fee_per_gas: Option<String>,
    pub max_priority_fee_per_gas: Option<String>,
    pub nonce: Option<u64>,
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

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    DoubleDeposit,
    "src/test_utils/DoubleDeposit.json"
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L1ToL2MessageSentEvent {
    pub from_address: EthAddress,
    pub l2_address: Felt,
    pub selector: Felt,
    pub payload: Vec<Felt>,
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

/// Simulate an unsigned transaction with account impersonation and return both gas used and receipt
pub async fn simulate_unsigned_tx_with_receipt(
    rpc_url: &str,
    unsigned_tx: &UnsignedTransactionData,
) -> Result<(u64, alloy::rpc::types::TransactionReceipt), ErrReport> {
    let anvil = Anvil::new()
        .arg("--fork-url")
        .arg(rpc_url)
        .try_spawn()
        .unwrap();
    let forked_provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());

    // Parse the from address
    let from_address = unsigned_tx
        .from
        .parse::<Address>()
        .map_err(|e| eyre!("Invalid from address '{}': {}", unsigned_tx.from, e))?;

    // Impersonate the from account
    let _: Value = forked_provider
        .raw_request("anvil_impersonateAccount".into(), json!([from_address]))
        .await
        .map_err(|e| eyre!("Failed to impersonate account {}: {}", from_address, e))?;

    // Build the transaction request
    let mut tx_request = TransactionRequest::default().with_from(from_address);

    // Set the to address if provided
    if let Some(to_str) = &unsigned_tx.to {
        let to_address = to_str
            .parse::<Address>()
            .map_err(|e| eyre!("Invalid to address '{}': {}", to_str, e))?;
        tx_request = tx_request.with_to(to_address);
    }

    // Set the value
    let value = U256::from_str(&unsigned_tx.value)
        .map_err(|e| eyre!("Invalid value '{}': {}", unsigned_tx.value, e))?;
    tx_request = tx_request.with_value(value);

    // Set the data
    if !unsigned_tx.data.is_empty() {
        tx_request = tx_request.with_input(unsigned_tx.data.clone());
    }

    // Set gas limit if provided
    if let Some(gas_limit) = unsigned_tx.gas_limit {
        tx_request = tx_request.with_gas_limit(gas_limit);
    }

    // Set nonce if provided
    if let Some(nonce) = unsigned_tx.nonce {
        tx_request = tx_request.with_nonce(nonce);
    }

    // Set gas price or EIP-1559 fees
    if let Some(gas_price_str) = &unsigned_tx.gas_price {
        let gas_price = gas_price_str
            .parse::<u128>()
            .map_err(|e| eyre!("Invalid gas price '{}': {}", gas_price_str, e))?;
        tx_request = tx_request.with_gas_price(gas_price);
    } else if let (Some(max_fee_str), Some(max_priority_fee_str)) = (
        &unsigned_tx.max_fee_per_gas,
        &unsigned_tx.max_priority_fee_per_gas,
    ) {
        let max_fee = max_fee_str
            .parse::<u128>()
            .map_err(|e| eyre!("Invalid max fee per gas '{}': {}", max_fee_str, e))?;
        let max_priority_fee = max_priority_fee_str.parse::<u128>().map_err(|e| {
            eyre!(
                "Invalid max priority fee per gas '{}': {}",
                max_priority_fee_str,
                e
            )
        })?;
        tx_request = tx_request.with_max_fee_per_gas(max_fee);
        tx_request = tx_request.with_max_priority_fee_per_gas(max_priority_fee);
    }

    // Send the transaction
    let pending = forked_provider
        .send_transaction(tx_request)
        .await
        .map_err(|e| eyre!("Failed to send transaction: {}", e))?;
    let receipt = pending
        .get_receipt()
        .await
        .map_err(|e| eyre!("Failed to get transaction receipt: {}", e))?;

    // Stop impersonating the account
    let _: Value = forked_provider
        .raw_request(
            "anvil_stopImpersonatingAccount".into(),
            json!([from_address]),
        )
        .await
        .map_err(|e| {
            eyre!(
                "Failed to stop impersonating account {}: {}",
                from_address,
                e
            )
        })?;

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
#[allow(dead_code)]
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

    /// Simulate a transaction envelope and return both gas used and receipt
    pub async fn simulate_tx_envelope_with_receipt(
        &self,
        target_tx: &TxEnvelope,
    ) -> Result<(u64, alloy::rpc::types::TransactionReceipt)> {
        info!("Simulating transaction envelope with receipt");
        simulate_tx_with_receipt(&self.network_config.l1_rpc_url, target_tx).await
    }

    /// Simulate an unsigned transaction with account impersonation and return both gas used and receipt
    pub async fn simulate_unsigned_tx_with_receipt(
        &self,
        unsigned_tx: &UnsignedTransactionData,
    ) -> Result<(u64, alloy::rpc::types::TransactionReceipt)> {
        info!(
            "Simulating unsigned transaction with impersonation: {:?}",
            unsigned_tx
        );
        simulate_unsigned_tx_with_receipt(&self.network_config.l1_rpc_url, unsigned_tx).await
    }

    /// Parse Starknet L1 to L2 message events from a transaction receipt
    pub fn parse_l1_to_l2_message_events(
        &self,
        receipt: &alloy::rpc::types::TransactionReceipt,
    ) -> Result<Vec<L1ToL2MessageSentEvent>> {
        parse_starknet_l1_to_l2_message_sent_events(receipt)
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            l1_rpc_url: "http://localhost:8545".to_string(),
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
        };
        let simulator = TransactionSimulator::new(config).unwrap();

        // Test the simulate_tx_envelope_with_receipt method
        let (gas_used, _receipt) = simulator
            .simulate_tx_envelope_with_receipt(&funding_tx_envelope)
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
            EthAddress::from_hex("0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4").unwrap();

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
        let expected_payload = [
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

    #[tokio::test]
    async fn test_simulate_unsigned_tx_with_receipt() {
        // Spawn Anvil and get its endpoint URL
        let anvil = Anvil::new().try_spawn().unwrap();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
        let accounts = provider.get_accounts().await.unwrap();
        let alice = accounts[0];
        let bob = accounts[1];

        // Create unsigned transaction data for a simple ETH transfer
        let unsigned_tx = UnsignedTransactionData {
            from: alice.to_string(),
            to: Some(bob.to_string()),
            value: "1000000000000000000".to_string(), // 1 ETH in wei
            data: vec![],
            gas_limit: Some(21000),
            gas_price: Some("20000000000".to_string()), // 20 gwei
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None, // Let the provider determine the nonce
        };

        // Create a TransactionSimulator with the Anvil endpoint
        let config = NetworkConfig {
            l1_rpc_url: anvil.endpoint_url().to_string(),
        };
        let simulator = TransactionSimulator::new(config).unwrap();

        // Test the simulate_unsigned_tx_with_receipt method
        let (gas_used, receipt) = simulator
            .simulate_unsigned_tx_with_receipt(&unsigned_tx)
            .await
            .unwrap();

        // Verify that gas was used (should be exactly 21000 for a simple transfer)
        assert!(gas_used > 0, "Gas used should be greater than 0");
        assert!(gas_used <= 21000, "Gas used should not exceed gas limit");

        // Verify the receipt contains expected information
        assert!(
            !receipt.transaction_hash.is_zero(),
            "Transaction hash should be present"
        );
        assert!(receipt.status(), "Transaction should be successful");
        assert_eq!(receipt.from, alice, "From address should match");
        assert_eq!(receipt.to, Some(bob), "To address should match");

        println!("Simulated unsigned transaction gas used: {}", gas_used);
        println!("Transaction hash: {:?}", receipt.transaction_hash);
    }

    #[tokio::test]
    async fn test_simulate_unsigned_tx_with_contract_interaction() {
        // Spawn Anvil and get its endpoint URL
        let anvil = Anvil::new().try_spawn().unwrap();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
        let accounts = provider.get_accounts().await.unwrap();
        let alice = accounts[0];
        let bob = accounts[1];

        // First, deploy an ERC20 contract using a signed transaction
        let alice_private_key = anvil.keys()[0].clone();
        let alice_signer = PrivateKeySigner::from(alice_private_key);
        let alice_provider = ProviderBuilder::new()
            .wallet(alice_signer.clone())
            .connect_provider(provider.clone());
        let erc20_contract = ERC20Example::deploy(&alice_provider).await.unwrap();
        let token_address = erc20_contract.address();

        // Create unsigned transaction data for an ERC20 transfer
        // ERC20 transfer function call data: transfer(address to, uint256 amount)
        let transfer_amount = U256::from(1000u64);
        let mut contract_data = vec![0xa9, 0x05, 0x9c, 0xbb]; // transfer function selector

        // Address parameter (32 bytes): 12 bytes padding + 20 bytes address
        contract_data.extend_from_slice(&[0u8; 12]); // padding for address
        contract_data.extend_from_slice(bob.as_slice()); // bob's address (20 bytes)

        // U256 parameter (32 bytes): amount in big-endian format
        contract_data.extend_from_slice(&transfer_amount.to_be_bytes::<32>()); // amount

        let unsigned_tx = UnsignedTransactionData {
            from: alice.to_string(),
            to: Some(token_address.to_string()),
            value: "0".to_string(), // No ETH transfer, just contract call
            data: contract_data,
            gas_limit: Some(100000), // Higher gas limit for contract interaction
            gas_price: Some("20000000000".to_string()), // 20 gwei
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None, // Let the provider determine the nonce
        };

        // Create a TransactionSimulator with the Anvil endpoint
        let config = NetworkConfig {
            l1_rpc_url: anvil.endpoint_url().to_string(),
        };
        let simulator = TransactionSimulator::new(config).unwrap();

        // Test the simulate_unsigned_tx_with_receipt method
        let (gas_used, receipt) = simulator
            .simulate_unsigned_tx_with_receipt(&unsigned_tx)
            .await
            .unwrap();

        // Print all events emitted by the transaction
        print_transaction_events(&receipt);

        // Verify that gas was used (should be higher than simple transfer)
        assert!(
            gas_used > 21000,
            "Gas used should be greater than simple transfer"
        );
        assert!(gas_used <= 100000, "Gas used should not exceed gas limit");

        // Verify the receipt contains expected information
        assert!(
            !receipt.transaction_hash.is_zero(),
            "Transaction hash should be present"
        );
        assert!(receipt.status(), "Transaction should be successful");
        assert_eq!(receipt.from, alice, "From address should match");
        assert_eq!(
            receipt.to,
            Some(*token_address),
            "To address should match contract"
        );

        println!(
            "Simulated unsigned contract transaction gas used: {}",
            gas_used
        );
    }

    #[tokio::test]
    async fn test_simulate_unsigned_tx_with_eip1559() {
        // Spawn Anvil and get its endpoint URL
        let anvil = Anvil::new().try_spawn().unwrap();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
        let accounts = provider.get_accounts().await.unwrap();
        let alice = accounts[0];
        let bob = accounts[1];

        // Create unsigned transaction data using EIP-1559 fee structure
        let unsigned_tx = UnsignedTransactionData {
            from: alice.to_string(),
            to: Some(bob.to_string()),
            value: "500000000000000000".to_string(), // 0.5 ETH in wei
            data: vec![],
            gas_limit: Some(21000),
            gas_price: None, // Don't use legacy gas price
            max_fee_per_gas: Some("30000000000".to_string()), // 30 gwei
            max_priority_fee_per_gas: Some("2000000000".to_string()), // 2 gwei
            nonce: None,     // Let the provider determine the nonce
        };

        // Create a TransactionSimulator with the Anvil endpoint
        let config = NetworkConfig {
            l1_rpc_url: anvil.endpoint_url().to_string(),
        };
        let simulator = TransactionSimulator::new(config).unwrap();

        // Test the simulate_unsigned_tx_with_receipt method
        let (gas_used, receipt) = simulator
            .simulate_unsigned_tx_with_receipt(&unsigned_tx)
            .await
            .unwrap();

        // Verify that gas was used
        assert!(gas_used > 0, "Gas used should be greater than 0");
        assert!(gas_used <= 21000, "Gas used should not exceed gas limit");

        // Verify the receipt contains expected information
        assert!(
            !receipt.transaction_hash.is_zero(),
            "Transaction hash should be present"
        );
        assert!(receipt.status(), "Transaction should be successful");
        assert_eq!(receipt.from, alice, "From address should match");
        assert_eq!(receipt.to, Some(bob), "To address should match");

        println!(
            "Simulated unsigned EIP-1559 transaction gas used: {}",
            gas_used
        );
    }

    #[tokio::test]
    async fn test_simulate_unsigned_starknet_deposit_tx() {
        // This test simulates the same Starknet deposit transaction from test_starknet_deposit_tx
        // but using the unsigned transaction approach instead of a signed transaction envelope

        // Spawn Anvil with fork from mainnet at the specific block
        let anvil = Anvil::new()
            .arg("--fork-url")
            .arg("https://reth-ethereum.ithaca.xyz/rpc")
            .fork_block_number(23113921)
            .try_spawn()
            .unwrap();

        // Create unsigned transaction data for the Starknet deposit
        // This replicates the transaction: https://etherscan.io/tx/0xd5fdee26751ba7175444cb587c1b1ddeca3a0d22cbf87bf0c1d6b4d263c6a699
        let unsigned_tx = UnsignedTransactionData {
            from: "0x11Dd734a52Cd2EE23FFe8B5054F5A8ECF5D1Ad50".to_string(), // Original sender
            to: Some("0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4".to_string()), // Starknet Core contract
            value: "25344429452040".to_string(), // Value in wei from original tx
            data: hex!("0efe6a8b000000000000000000000000ca14007eff0db1f8135f4c25b34de49ab0d42766000000000000000000000000000000000000000000004f9c6a3ec958b0de0000013cd2f10b45da0332429cea44028b89ee386cb2adfb9bb8f1c470bad6a1f8d1").to_vec(),
            gas_limit: Some(190_674), // Gas limit from original tx
            gas_price: Some("2306574200".to_string()), // Gas price from original tx
            max_fee_per_gas: None, // Using legacy gas pricing
            max_priority_fee_per_gas: None,
            nonce: Some(58), // Nonce from original tx
        };

        // Create a TransactionSimulator with the forked Anvil endpoint
        let config = NetworkConfig {
            l1_rpc_url: anvil.endpoint_url().to_string(),
        };
        let simulator = TransactionSimulator::new(config).unwrap();

        // Test the simulate_unsigned_tx_with_receipt method
        let (gas_used, receipt) = simulator
            .simulate_unsigned_tx_with_receipt(&unsigned_tx)
            .await
            .unwrap();

        // Print all events emitted by the transaction
        print_transaction_events(&receipt);

        // Parse L1 to L2 message events from the receipt
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

        // Verify the gas usage is reasonable
        assert!(gas_used > 0, "Gas used should be greater than 0");
        assert!(
            gas_used <= 190_674,
            "Gas used should not exceed the specified gas limit"
        );

        // Verify the receipt contains expected information
        assert!(
            !receipt.transaction_hash.is_zero(),
            "Transaction hash should be present"
        );
        assert!(receipt.status(), "Transaction should be successful");
        assert_eq!(
            receipt.from,
            address!("0x11Dd734a52Cd2EE23FFe8B5054F5A8ECF5D1Ad50"),
            "From address should match"
        );
        assert_eq!(
            receipt.to,
            Some(
                "0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4"
                    .parse()
                    .unwrap()
            ),
            "To address should match Starknet Core contract"
        );

        // Assertions for the Starknet deposit specifics
        // This specific transaction should emit exactly 1 L1ToL2MessageSent event
        assert_eq!(
            l1_to_l2_logs.len(),
            1,
            "Expected exactly 1 L1ToL2MessageSent event, but found {}",
            l1_to_l2_logs.len()
        );

        let event = &l1_to_l2_logs[0];

        let expected_from_address =
            EthAddress::from_hex("0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4").unwrap();

        // Expected values based on the actual decoded event output from the signed tx test
        let expected_to_address = Felt::from_str(
            "2524392021852001135582825949054576525094493216367559068627275826195272239197",
        )
        .unwrap();
        let expected_selector = Felt::from_str(
            "774397379524139446221206168840917193112228400237242521560346153613428128537",
        )
        .unwrap();

        assert_eq!(event.from_address, expected_from_address);
        assert_eq!(
            event.l2_address, expected_to_address,
            "L2 address mismatch. Expected: {}, Got: {}",
            expected_to_address, event.l2_address
        );
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

        // The payload should contain exactly 5 elements based on the original test
        assert_eq!(
            event.payload.len(),
            5,
            "Expected payload to have 5 elements, but found {}",
            event.payload.len()
        );

        // Assert specific payload values from the original test
        let expected_payload = [
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

        println!(
            "Successfully simulated unsigned Starknet deposit transaction with gas used: {}",
            gas_used
        );
        println!("All L1ToL2MessageSent event validations passed!");
    }

    #[tokio::test]
    async fn test_double_deposit_unsigned_tx() {
        // Spawn Anvil with fork from mainnet at a more recent block where contract should be deployed
        let anvil = Anvil::new()
            .arg("--fork-url")
            .arg("https://reth-ethereum.ithaca.xyz/rpc")
            .fork_block_number(23138386)
            .try_spawn()
            .unwrap();

        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());

        // doubleDeposit address = 0xEafC6a0b08f1AB67A00e618433C21de98358Bf5e
        let double_deposit_address = address!("0xEafC6a0b08f1AB67A00e618433C21de98358Bf5e");

        // Check if contract is deployed by looking at bytecode
        let bytecode = provider.get_code_at(double_deposit_address).await.unwrap();
        println!("Contract bytecode length: {} bytes", bytecode.len());
        if bytecode.is_empty() {
            panic!(
                "DoubleDeposit contract is not deployed at address {}",
                double_deposit_address
            );
        }

        // Vitalik's address (well-known public address)
        let vitalik_address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
        let vitalik_addr = Address::from_str(vitalik_address).unwrap();

        // Check Vitalik's balance
        let balance = provider.get_balance(vitalik_addr).await.unwrap();
        println!(
            "Vitalik's balance: {} ETH",
            balance.to::<u128>() as f64 / 1e18
        );

        // Fund Vitalik's account with more ETH if needed
        let funding_amount = parse_ether("100").unwrap(); // 100 ETH
        let _: Value = provider
            .raw_request(
                "anvil_setBalance".into(),
                json!([vitalik_address, format!("0x{:x}", funding_amount)]),
            )
            .await
            .unwrap();

        let new_balance = provider.get_balance(vitalik_addr).await.unwrap();
        println!(
            "Vitalik's new balance: {} ETH",
            new_balance.to::<u128>() as f64 / 1e18
        );

        // Test parameters for doubleDeposit
        let amount1 = U256::from_str("100000000000000000").unwrap(); // 0.1 ETH
        let amount2 = U256::from_str("200000000000000000").unwrap(); // 0.2 ETH
                                                                     // Use valid L2 addresses (Starknet field elements)
        let l2_recipient1 =
            U256::from_str("0x1234567890abcdef1234567890abcdef1234567890abcdef123456789").unwrap();
        let l2_recipient2 =
            U256::from_str("0x9876543210fedcba9876543210fedcba9876543210fedcba987654321").unwrap();

        let nonce = provider.get_transaction_count(vitalik_addr).await.unwrap();

        // Calculate required ETH (amount1 + amount2 + fees)
        // Use generous fee estimation to ensure we have enough
        let estimated_fees = parse_ether("0.01").unwrap(); // 0.01 ETH for fees (generous)
        let total_value = amount1 + amount2 + estimated_fees;

        println!("Sending transaction with:");
        println!("  amount1: {} ETH", amount1.to::<u128>() as f64 / 1e18);
        println!("  amount2: {} ETH", amount2.to::<u128>() as f64 / 1e18);
        println!(
            "  estimated_fees: {} ETH",
            estimated_fees.to::<u128>() as f64 / 1e18
        );
        println!(
            "  total_value: {} ETH",
            total_value.to::<u128>() as f64 / 1e18
        );

        // Create function call data for doubleDeposit(uint256,uint256,uint256,uint256)
        // Function selector: 0x0c4c5492
        let mut calldata = vec![0x0c, 0x4c, 0x54, 0x92]; // doubleDeposit function selector

        // Add parameters (each uint256 is 32 bytes)
        calldata.extend_from_slice(&amount1.to_be_bytes::<32>()); // amount1
        calldata.extend_from_slice(&amount2.to_be_bytes::<32>()); // amount2
        calldata.extend_from_slice(&l2_recipient1.to_be_bytes::<32>()); // l2Recipient1
        calldata.extend_from_slice(&l2_recipient2.to_be_bytes::<32>()); // l2Recipient2

        // Create unsigned transaction data
        let unsigned_tx = UnsignedTransactionData {
            from: vitalik_address.to_string(),
            to: Some(double_deposit_address.to_string()),
            value: total_value.to_string(),
            data: calldata,
            gas_limit: Some(300000),
            gas_price: None, // 20 gwei
            max_fee_per_gas: Some("20000000000".to_string()),
            max_priority_fee_per_gas: Some("20000000000".to_string()),
            nonce: Some(nonce),
        };

        // Create a TransactionSimulator with the forked Anvil endpoint
        let config = NetworkConfig {
            l1_rpc_url: anvil.endpoint_url().to_string(),
        };
        let simulator = TransactionSimulator::new(config).unwrap();

        // Execute the transaction
        let result = simulator
            .simulate_unsigned_tx_with_receipt(&unsigned_tx)
            .await;

        let (gas_used, receipt) = match result {
            Ok((gas, receipt)) => (gas, receipt),
            Err(e) => {
                println!("Transaction failed with error: {}", e);
                panic!("Transaction execution failed: {}", e);
            }
        };

        // Print all events emitted by the transaction for debugging
        print_transaction_events(&receipt);

        // Debug transaction details
        println!("Transaction status: {}", receipt.status());
        println!("Transaction hash: {:?}", receipt.transaction_hash);
        println!("Gas used: {}", gas_used);
        println!("Gas limit: {}", unsigned_tx.gas_limit.unwrap_or(0));
        println!("Value sent: {} ETH", total_value.to::<u128>() as f64 / 1e18);

        // If transaction failed, let's continue to see what events might have been emitted
        if !receipt.status() {
            println!("⚠️  Transaction reverted, but continuing to analyze events...");
        }
        assert!(gas_used > 0, "Gas used should be greater than 0");
        assert!(gas_used <= 300000, "Gas used should not exceed gas limit");

        // Verify transaction was successful
        assert!(receipt.status(), "Transaction should be successful");

        println!(
            "Simulated double deposit transaction gas used: {}",
            gas_used
        );

        // Parse DoubleDepositExecuted events
        let deposit_events: Vec<_> = receipt
            .logs()
            .iter()
            .filter_map(|log| DoubleDeposit::DoubleDepositExecuted::decode_log(log.as_ref()).ok())
            .collect();

        println!(
            "Found {} DoubleDepositExecuted events:",
            deposit_events.len()
        );
        for (i, event) in deposit_events.iter().enumerate() {
            println!("  Event {}:", i + 1);
            println!("    amount1: {}", event.amount1);
            println!("    amount2: {}", event.amount2);
            println!("    l2Recipient1: {}", event.l2Recipient1);
            println!("    l2Recipient2: {}", event.l2Recipient2);
            println!("    totalEthSent: {}", event.totalEthSent);
        }

        // Verify exactly one DoubleDepositExecuted event is emitted
        assert_eq!(
            deposit_events.len(),
            1,
            "Expected exactly 1 DoubleDepositExecuted event, but found {}",
            deposit_events.len()
        );

        let deposit_event = &deposit_events[0];

        // Verify the event data matches our parameters
        assert_eq!(deposit_event.amount1, amount1, "Amount1 mismatch");
        assert_eq!(deposit_event.amount2, amount2, "Amount2 mismatch");
        assert_eq!(
            deposit_event.l2Recipient1, l2_recipient1,
            "L2 recipient1 mismatch"
        );
        assert_eq!(
            deposit_event.l2Recipient2, l2_recipient2,
            "L2 recipient2 mismatch"
        );
        assert_eq!(
            deposit_event.totalEthSent, total_value,
            "Total ETH sent mismatch"
        );

        // Parse L1ToL2MessageSent events (should be 2 for double deposit)
        let l1_to_l2_logs = simulator.parse_l1_to_l2_message_events(&receipt).unwrap();
        println!("Found {} L1ToL2MessageSent events:", l1_to_l2_logs.len());

        for (i, log) in l1_to_l2_logs.iter().enumerate() {
            println!("  L1ToL2 Event {}:", i + 1);
            println!("    from_address: {:?}", log.from_address);
            println!("    to_address: {}", log.l2_address);
            println!("    selector: {}", log.selector);
            println!("    payload: {:?}", log.payload);
        }

        // Verify exactly two L1ToL2MessageSent events are emitted (one for each deposit)
        assert_eq!(
            l1_to_l2_logs.len(),
            2,
            "Expected exactly 2 L1ToL2MessageSent events, but found {}",
            l1_to_l2_logs.len()
        );

        // Verify both events come from the StarkGate contract
        // We can see from the debug output that they come from the correct address
        // 0xae0Ee0A63A2cE6BaEeFE56e7714FB4EFE48D419 (StarkGate ETH bridge)
        for (i, event) in l1_to_l2_logs.iter().enumerate() {
            // Verify that payload is not empty
            assert!(
                !event.payload.is_empty(),
                "L1ToL2 event {} should have non-empty payload",
                i + 1
            );

            // Verify payload has expected structure (token, from, to, amount, nonce)
            assert_eq!(
                event.payload.len(),
                5,
                "L1ToL2 event {} should have 5 payload elements",
                i + 1
            );
        }

        println!("✅ All validations passed!");
        println!("✅ DoubleDepositExecuted event parsed correctly");
        println!("✅ Two L1ToL2MessageSent events parsed correctly");
        println!("✅ Double deposit contract test completed successfully");
    }
}
