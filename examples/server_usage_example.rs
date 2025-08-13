use estimate_starknet_message_fee::server::RpcServer;
use reqwest::Client;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::{sleep, timeout};

/// Example demonstrating how to start the server and use all its API endpoints
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🚀 Starting Starknet Message Fee Estimation Server Example");

    // 1. Start the server
    let addr = start_server().await?;
    println!("✅ Server started on {}", addr);

    // 2. Wait a moment for the server to fully initialize
    sleep(Duration::from_millis(500)).await;

    // 3. Test all API endpoints
    test_estimate_l1_to_l2_message_fees().await?;
    test_estimate_from_unsigned_transaction().await?;
    test_estimate_from_signed_transaction().await?;

    println!("🎉 All examples completed successfully!");
    println!(
        "💡 The server is still running on {} for manual testing",
        addr
    );
    println!("📖 You can now test it manually using curl:");
    println!();
    println!("curl -X POST -H \"Content-Type: application/json\" \\");
    println!("  --data '{{\"jsonrpc\":\"2.0\",\"method\":\"estimate_l1_to_l2_message_fees_from_unsigned_tx\",\"params\":[{{\"from\":\"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\",\"to\":\"0x70997970C51812dc3A010C7d01b50e0d17dc79C8\",\"value\":\"1000000000000000000\"}}],\"id\":1}}' \\");
    println!("  http://{}", addr);
    println!();

    // Keep the server running for manual testing
    loop {
        sleep(Duration::from_secs(10)).await;
    }
}

/// Start the server in the background and return its address
async fn start_server() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;

    // Create server with default configuration
    let server = RpcServer::new()?;

    // Start the server in a background task
    tokio::spawn(async move {
        if let Err(e) = server.start(addr).await {
            eprintln!("❌ Server error: {}", e);
        }
    });

    // Wait for the server to start accepting connections
    let client = Client::new();
    let mut attempts = 0;
    let max_attempts = 50;

    println!("⏳ Waiting for server to start...");
    while attempts < max_attempts {
        if let Ok(response) = client
            .post(&format!("http://{}", addr))
            .header("Content-Type", "application/json")
            .json(&json!({
                "jsonrpc": "2.0",
                "method": "estimate_l1_to_l2_message_fees",
                "params": [{"messages": []}],
                "id": 1
            }))
            .send()
            .await
        {
            if response.status().is_success() || response.status().is_client_error() {
                break;
            }
        }
        sleep(Duration::from_millis(100)).await;
        attempts += 1;
    }

    if attempts >= max_attempts {
        return Err("Server failed to start within timeout".into());
    }

    Ok(addr)
}

/// Send a JSON-RPC request to the server
async fn send_rpc_request(
    method: &str,
    params: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let client = Client::new();
    let url = "http://127.0.0.1:8080";

    let request_body = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    println!(
        "📤 Sending request to {}: {}",
        method,
        serde_json::to_string_pretty(&request_body)?
    );

    let response = timeout(
        Duration::from_secs(30),
        client
            .post(url)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send(),
    )
    .await??;

    let response_json: Value = response.json().await?;
    println!(
        "📥 Response: {}",
        serde_json::to_string_pretty(&response_json)?
    );

    Ok(response_json)
}

/// Test direct L1 to L2 message fee estimation
async fn test_estimate_l1_to_l2_message_fees() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🧪 Testing estimate_l1_to_l2_message_fees endpoint");
    println!("{}", "=".repeat(60));

    let params = json!([{
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
    }]);

    let response = send_rpc_request("estimate_l1_to_l2_message_fees", params).await?;

    if let Some(error) = response.get("error") {
        println!(
            "⚠️  Expected error (likely due to network configuration): {}",
            error
        );
    } else if let Some(result) = response.get("result") {
        println!("✅ Success: {}", result);
    }

    Ok(())
}

/// Test fee estimation from unsigned transaction
async fn test_estimate_from_unsigned_transaction() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🧪 Testing estimate_l1_to_l2_message_fees_from_unsigned_tx endpoint");
    println!("{}", "=".repeat(60));

    // Example 1: Simple ETH transfer
    println!("📝 Example 1: Simple ETH transfer");
    let params = json!([{
        "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "value": "1000000000000000000", // 1 ETH in wei
        "data": "0x",
        "gas": 21000,
        "gasPrice": "20000000000" // 20 gwei
    }]);

    let response =
        send_rpc_request("estimate_l1_to_l2_message_fees_from_unsigned_tx", params).await?;

    if let Some(error) = response.get("error") {
        println!(
            "⚠️  Expected error (likely due to network configuration): {}",
            error
        );
    } else if let Some(result) = response.get("result") {
        println!("✅ Success: {}", result);
    }

    // Example 2: EIP-1559 transaction
    println!("\n📝 Example 2: EIP-1559 transaction");
    let params_eip1559 = json!([{
        "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "value": "500000000000000000", // 0.5 ETH in wei
        "data": "0x",
        "gas": 21000,
        "maxFeePerGas": "30000000000", // 30 gwei
        "maxPriorityFeePerGas": "2000000000" // 2 gwei
    }]);

    let response = send_rpc_request(
        "estimate_l1_to_l2_message_fees_from_unsigned_tx",
        params_eip1559,
    )
    .await?;

    if let Some(error) = response.get("error") {
        println!(
            "⚠️  Expected error (likely due to network configuration): {}",
            error
        );
    } else if let Some(result) = response.get("result") {
        println!("✅ Success: {}", result);
    }

    // Example 3: Contract interaction with data
    println!("\n📝 Example 3: Contract interaction with data");
    let params_contract = json!([{
        "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "to": "0xA0b86a33E6fF3Cc546a8aD5BECB91Dc32A0EAdE",
        "value": "0",
        "data": "0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b8d0b2f0e8e6f5dabb0000000000000000000000000000000000000000000000000de0b6b3a7640000", // ERC20 transfer
        "gas": 60000,
        "gasPrice": "25000000000" // 25 gwei
    }]);

    let response = send_rpc_request(
        "estimate_l1_to_l2_message_fees_from_unsigned_tx",
        params_contract,
    )
    .await?;

    if let Some(error) = response.get("error") {
        println!(
            "⚠️  Expected error (likely due to network configuration): {}",
            error
        );
    } else if let Some(result) = response.get("result") {
        println!("✅ Success: {}", result);
    }

    Ok(())
}

/// Test fee estimation from signed transaction
async fn test_estimate_from_signed_transaction() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n🧪 Testing estimate_l1_to_l2_message_fees_from_signed_tx endpoint");
    println!("{}", "=".repeat(60));

    // Example with a mock signed transaction (in practice, this would be a real signed transaction)
    let params = json!(["0xf86c808509184e72a00082520894d46e8dd67c5d32be8058bb8eb970870f07244567849184e72aa9d46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445678025a0c9cf86333bcb065d971d8e62a6b6b8b2c7c2e4b5a2e3a9e2b8c2e4b5a2e3a9e2c0"]);

    let response =
        send_rpc_request("estimate_l1_to_l2_message_fees_from_signed_tx", params).await?;

    if let Some(error) = response.get("error") {
        println!("⚠️  Expected error (likely due to invalid mock transaction or network configuration): {}", error);
    } else if let Some(result) = response.get("result") {
        println!("✅ Success: {}", result);
    }

    Ok(())
}
