use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;

/// Simple client example showing how to call the server API
///
/// This example assumes the server is already running on localhost:8080
/// Start the server first with: `cargo run` or use the server_usage_example.rs
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔌 Starknet Message Fee Estimation Client Example");
    println!("📋 This example shows how to call the server API endpoints");
    println!("⚠️  Make sure the server is running on localhost:8080 first!");
    println!();

    // Test each endpoint
    test_unsigned_transaction_fee_estimation().await?;
    test_direct_message_fee_estimation().await?;

    Ok(())
}

/// Test fee estimation for unsigned transactions
async fn test_unsigned_transaction_fee_estimation() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Testing Unsigned Transaction Fee Estimation");
    println!("{}", "=".repeat(50));

    let client = Client::new();
    let url = "http://127.0.0.1:8080";

    // Example 1: Simple ETH transfer
    println!("📝 Example 1: Simple ETH transfer");
    let request = json!({
        "jsonrpc": "2.0",
        "method": "estimate_l1_to_l2_message_fees_from_unsigned_tx",
        "params": [{
            "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "value": "1000000000000000000", // 1 ETH
            "gas": 21000,
            "gasPrice": "20000000000" // 20 gwei
        }],
        "id": 1
    });

    println!("📤 Request: {}", serde_json::to_string_pretty(&request)?);

    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .timeout(Duration::from_secs(30))
        .json(&request)
        .send()
        .await?;

    let response_json: Value = response.json().await?;
    println!(
        "📥 Response: {}",
        serde_json::to_string_pretty(&response_json)?
    );

    // Example 2: ERC20 token transfer
    println!("\n📝 Example 2: ERC20 token transfer");
    let request = json!({
        "jsonrpc": "2.0",
        "method": "estimate_l1_to_l2_message_fees_from_unsigned_tx",
        "params": [{
            "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "to": "0xA0b86a33E6fF3Cc546a8aD5BECB91Dc32A0EAdE", // ERC20 contract address
            "value": "0",
            "data": "0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b8d0b2f0e8e6f5dabb0000000000000000000000000000000000000000000000000de0b6b3a7640000", // transfer(address,uint256)
            "gas": 60000,
            "gasPrice": "25000000000" // 25 gwei
        }],
        "id": 2
    });

    println!("📤 Request: {}", serde_json::to_string_pretty(&request)?);

    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .timeout(Duration::from_secs(30))
        .json(&request)
        .send()
        .await?;

    let response_json: Value = response.json().await?;
    println!(
        "📥 Response: {}",
        serde_json::to_string_pretty(&response_json)?
    );

    // Example 3: EIP-1559 transaction
    println!("\n📝 Example 3: EIP-1559 transaction");
    let request = json!({
        "jsonrpc": "2.0",
        "method": "estimate_l1_to_l2_message_fees_from_unsigned_tx",
        "params": [{
            "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "value": "500000000000000000", // 0.5 ETH
            "gas": 21000,
            "maxFeePerGas": "30000000000",      // 30 gwei
            "maxPriorityFeePerGas": "2000000000" // 2 gwei
        }],
        "id": 3
    });

    println!("📤 Request: {}", serde_json::to_string_pretty(&request)?);

    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .timeout(Duration::from_secs(30))
        .json(&request)
        .send()
        .await?;

    let response_json: Value = response.json().await?;
    println!(
        "📥 Response: {}",
        serde_json::to_string_pretty(&response_json)?
    );

    Ok(())
}

/// Test direct message fee estimation
async fn test_direct_message_fee_estimation() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🧪 Testing Direct Message Fee Estimation");
    println!("{}", "=".repeat(50));

    let client = Client::new();
    let url = "http://127.0.0.1:8080";

    let request = json!({
        "jsonrpc": "2.0",
        "method": "estimate_l1_to_l2_message_fees",
        "params": [{
            "messages": [
                {
                    "from_address": "0x8453FC6Cd1bCfE8D4dFC069C400B433054d47bDc",
                    "l2_address": "0x04c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f",
                    "selector": "0x02d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
                    "payload": [
                        "0x0000000000000000000000008453FC6Cd1bCfE8D4dFC069C400B433054d47bDc",
                        "0x00000000000000000000000000000000000000000000000000000000000003e8"
                    ]
                }
            ]
        }],
        "id": 4
    });

    println!("📤 Request: {}", serde_json::to_string_pretty(&request)?);

    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .timeout(Duration::from_secs(30))
        .json(&request)
        .send()
        .await?;

    let response_json: Value = response.json().await?;
    println!(
        "📥 Response: {}",
        serde_json::to_string_pretty(&response_json)?
    );

    Ok(())
}
