use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;

/// Working client example showing how to call the Starknet fee estimation server API
///
/// This example assumes the server is already running on localhost:8080
/// Start the server first with: `cargo run` or use the server_usage_example.rs
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔌 Starknet Message Fee Estimation Client Example");
    println!("📋 This example shows how to call the server API endpoints");
    println!("⚠️  Make sure the server is running on localhost:8080 first!");
    println!();

    // Test each endpoint with real Starknet deposit examples
    test_double_starknet_deposit().await?;
    test_direct_message_fee_estimation().await?;

    Ok(())
}

/// Test fee estimation for a double Starknet deposit transaction
/// Based on the working test: test_double_deposit_unsigned_tx
async fn test_double_starknet_deposit() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🧪 Testing Double Starknet Deposit Fee Estimation");
    println!("{}", "=".repeat(50));

    let client = Client::new();
    let url = "http://127.0.0.1:8080";

    // Create function call data for doubleDeposit(uint256,uint256,uint256,uint256)
    // Function selector: 0x0c4c5492
    let amount1 = "100000000000000000"; // 0.1 ETH in wei
    let amount2 = "200000000000000000"; // 0.2 ETH in wei
    let l2_recipient1 = "0x1234567890abcdef1234567890abcdef1234567890abcdef123456789"; // Valid L2 address
    let l2_recipient2 = "0x9876543210fedcba9876543210fedcba9876543210fedcba987654321"; // Valid L2 address

    // Build the calldata for doubleDeposit function
    let mut calldata = "0x0c4c5492".to_string(); // doubleDeposit function selector

    // Convert amounts to hex (32 bytes each)
    let amount1_hex = format!("{:0>64}", format!("{:x}", amount1.parse::<u128>().unwrap()));
    let amount2_hex = format!("{:0>64}", format!("{:x}", amount2.parse::<u128>().unwrap()));
    let l2_recipient1_hex = format!(
        "{:0>64}",
        l2_recipient1.strip_prefix("0x").unwrap_or(l2_recipient1)
    );
    let l2_recipient2_hex = format!(
        "{:0>64}",
        l2_recipient2.strip_prefix("0x").unwrap_or(l2_recipient2)
    );

    calldata.push_str(&amount1_hex);
    calldata.push_str(&amount2_hex);
    calldata.push_str(&l2_recipient1_hex);
    calldata.push_str(&l2_recipient2_hex);

    let total_value = (amount1.parse::<u128>().unwrap()
        + amount2.parse::<u128>().unwrap()
        + 10000000000000000u128)
        .to_string(); // amounts + 0.01 ETH for fees

    println!("📝 Double Starknet ETH Deposit");
    let request = json!({
        "jsonrpc": "2.0",
        "method": "estimate_l1_to_l2_message_fees_from_unsigned_tx",
        "params": [{
            "from": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", // Vitalik's address (well-funded)
            "to": "0xEafC6a0b08f1AB67A00e618433C21de98358Bf5e", // DoubleDeposit contract
            "value": total_value,
            "data": calldata,
            "gas": 300000,
            "maxFeePerGas": "20000000000",      // 20 gwei
            "maxPriorityFeePerGas": "20000000000" // 20 gwei
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

    Ok(())
}

/// Test direct message fee estimation using already parsed L1ToL2MessageSent events
async fn test_direct_message_fee_estimation() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🧪 Testing Direct Message Fee Estimation");
    println!("{}", "=".repeat(50));

    let client = Client::new();
    let url = "http://127.0.0.1:8080";

    // Example of directly providing L1ToL2MessageSent event data
    // This might come from parsing transaction receipts or event logs
    let request = json!({
        "jsonrpc": "2.0",
        "method": "estimate_l1_to_l2_message_fees",
        "params": [{
            "messages": [
                {
                    "from_address": "0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4", // Starknet Core contract
                    "l2_address": "0x594c1582459ea03f77deaf9eb7e3917d6994a03c13405ba42867f83d85f085d", // L2 contract address
                    "selector": "0x1b64b1b3b690b43b9b514fb81377518f4039cd3e4f4914d8a6bdf01d679fb19", // Function selector on L2
                    "payload": [
                        "0xca14007eff0db1f8135f4c25b34de49ab0d42766", // Recipient address
                        "0x11dd734a52cd2ee23ffe8b5054f5a8ecf5d1ad50", // Sender address
                        "0x13cd2f10b45da0332429cea44028b89ee386cb2adfb9bb8f1c470bad6a1f8d1", // Additional data
                        "0x4f9c6a3ec958b0de0000", // Amount
                        "0x0" // Nonce or additional parameter
                    ]
                }
            ]
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
