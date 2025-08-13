use estimate_starknet_message_fee::simulator::{
    NetworkConfig, TransactionSimulator, UnsignedTransactionData,
};
use eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Example demonstrating how to use simulate_unsigned_tx_with_receipt

    // 1. Create a network configuration with your RPC URL
    let config = NetworkConfig {
        l1_rpc_url: "https://eth.llamarpc.com".to_string(), // Replace with your RPC URL
        block_number: None,                                 // Use latest block
    };

    // 2. Create a transaction simulator
    let simulator = TransactionSimulator::new(config)?;

    // 3. Create unsigned transaction data
    let unsigned_tx = UnsignedTransactionData {
        from: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(), // Sender address
        to: Some("0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string()), // Recipient address
        value: "1000000000000000000".to_string(),                       // 1 ETH in wei
        data: vec![],                               // No data for simple transfer
        gas_limit: Some(21000),                     // Standard gas limit for ETH transfer
        gas_price: Some("20000000000".to_string()), // 20 gwei
        max_fee_per_gas: None,                      // Optional: use for EIP-1559 transactions
        max_priority_fee_per_gas: None,             // Optional: use for EIP-1559 transactions
        nonce: None,                                // Let the provider determine the nonce
    };

    // 4. Simulate the unsigned transaction
    println!("Simulating unsigned transaction...");
    let (gas_used, receipt) = simulator
        .simulate_unsigned_tx_with_receipt(&unsigned_tx)
        .await?;

    // 5. Display the results
    println!("Simulation successful!");
    println!("Gas used: {}", gas_used);
    println!("Transaction hash: {:?}", receipt.transaction_hash);
    println!("Transaction status: {:?}", receipt.status());
    println!("From: {}", receipt.from);
    println!("To: {:?}", receipt.to);

    // Example with EIP-1559 transaction
    let unsigned_tx_eip1559 = UnsignedTransactionData {
        from: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".to_string(),
        to: Some("0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string()),
        value: "500000000000000000".to_string(), // 0.5 ETH
        data: vec![],
        gas_limit: Some(21000),
        gas_price: None, // Don't use legacy gas price
        max_fee_per_gas: Some("30000000000".to_string()), // 30 gwei
        max_priority_fee_per_gas: Some("2000000000".to_string()), // 2 gwei
        nonce: None,
    };

    println!("\nSimulating EIP-1559 unsigned transaction...");
    let (gas_used_eip1559, receipt_eip1559) = simulator
        .simulate_unsigned_tx_with_receipt(&unsigned_tx_eip1559)
        .await?;

    println!("EIP-1559 simulation successful!");
    println!("Gas used: {}", gas_used_eip1559);
    println!("Transaction hash: {:?}", receipt_eip1559.transaction_hash);

    Ok(())
}
