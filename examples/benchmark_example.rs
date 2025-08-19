use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Barrier;
use tokio::time::sleep;

/// Standalone benchmark example for the Starknet fee estimation server
/// Run with: cargo run --example benchmark_example
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Starknet Fee Estimation Server Benchmark");
    println!("{}", "=".repeat(50));
    println!("⚠️  Make sure the server is running on localhost:8080 first!");
    println!("   Start with: cargo run");
    println!();

    // Wait a moment for user to read instructions
    sleep(Duration::from_secs(2)).await;

    // Test both endpoints with different concurrency levels
    println!("\n🧪 Testing Direct L1 to L2 Message Fee Estimation");
    run_parallel_benchmark(5, 20, EndpointType::DirectMessage).await?;
    run_parallel_benchmark(10, 10, EndpointType::DirectMessage).await?;
    run_parallel_benchmark(20, 5, EndpointType::DirectMessage).await?;

    println!("\n🧪 Testing Unsigned Transaction Fee Estimation");
    run_parallel_benchmark(5, 10, EndpointType::UnsignedTx).await?;
    run_parallel_benchmark(10, 5, EndpointType::UnsignedTx).await?;
    run_parallel_benchmark(20, 3, EndpointType::UnsignedTx).await?;

    println!("\n✅ Benchmark completed successfully");
    Ok(())
}

#[derive(Clone, Copy)]
enum EndpointType {
    DirectMessage,
    UnsignedTx,
}

async fn run_parallel_benchmark(
    num_clients: usize,
    requests_per_client: usize,
    endpoint_type: EndpointType,
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint_name = match endpoint_type {
        EndpointType::DirectMessage => "Direct Message",
        EndpointType::UnsignedTx => "Unsigned Transaction",
    };

    println!(
        "\n📊 Benchmark: {} clients × {} requests each ({})",
        num_clients, requests_per_client, endpoint_name
    );
    println!("{}", "-".repeat(50));

    let start_time = Instant::now();
    let barrier = Arc::new(Barrier::new(num_clients));
    let mut handles = Vec::new();

    // Spawn client tasks
    for client_id in 0..num_clients {
        let barrier = barrier.clone();
        let endpoint_type = endpoint_type;
        let handle = tokio::spawn(async move {
            // Wait for all clients to be ready
            barrier.wait().await;

            let client = Client::new();
            let url = "http://127.0.0.1:8080";
            let mut success_count = 0;
            let mut error_count = 0;

            for request_id in 0..requests_per_client {
                match send_test_request(&client, url, client_id, request_id, endpoint_type).await {
                    Ok(_) => success_count += 1,
                    Err(_) => error_count += 1,
                }
            }

            (success_count, error_count)
        });
        handles.push(handle);
    }

    // Wait for all clients to complete
    let mut total_success = 0;
    let mut total_errors = 0;

    for handle in handles {
        let (success, errors) = handle.await?;
        total_success += success;
        total_errors += errors;
    }

    let duration = start_time.elapsed();
    let total_requests = num_clients * requests_per_client;
    let requests_per_second = total_success as f64 / duration.as_secs_f64();

    println!("⏱️  Duration: {:.2}s", duration.as_secs_f64());
    println!(
        "✅ Successful requests: {}/{}",
        total_success, total_requests
    );
    println!("❌ Failed requests: {}/{}", total_errors, total_requests);
    println!("🚀 Requests per second: {:.2}", requests_per_second);
    println!(
        "📈 Success rate: {:.1}%",
        (total_success as f64 / total_requests as f64) * 100.0
    );

    Ok(())
}

async fn send_test_request(
    client: &Client,
    url: &str,
    client_id: usize,
    request_id: usize,
    endpoint_type: EndpointType,
) -> Result<(), Box<dyn std::error::Error>> {
    let request = match endpoint_type {
        EndpointType::DirectMessage => {
            // Direct L1 to L2 message fee estimation
            json!({
                "jsonrpc": "2.0",
                "method": "estimate_l1_to_l2_message_fees",
                "params": [{
                    "messages": [
                        {
                            "from_address": "0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4",
                            "l2_address": "0x594c1582459ea03f77deaf9eb7e3917d6994a03c13405ba42867f83d85f085d",
                            "selector": "0x1b64b1b3b690b43b9b514fb81377518f4039cd3e4f4914d8a6bdf01d679fb19",
                            "payload": [
                                "0xca14007eff0db1f8135f4c25b34de49ab0d42766",
                                "0x11dd734a52cd2ee23ffe8b5054f5a8ecf5d1ad50",
                                "0x13cd2f10b45da0332429cea44028b89ee386cb2adfb9bb8f1c470bad6a1f8d1",
                                "0x4f9c6a3ec958b0de0000",
                                "0x0"
                            ]
                        }
                    ]
                }],
                "id": client_id * 1000 + request_id
            })
        }
        EndpointType::UnsignedTx => {
            // Unsigned transaction fee estimation (simulates a double deposit)
            let amount1 = "100000000000000000"; // 0.1 ETH
            let amount2 = "200000000000000000"; // 0.2 ETH
            let l2_recipient1 = "0x1234567890abcdef1234567890abcdef1234567890abcdef123456789";
            let l2_recipient2 = "0x9876543210fedcba9876543210fedcba9876543210fedcba987654321";

            // Build calldata for doubleDeposit function
            let mut calldata = "0x0c4c5492".to_string(); // doubleDeposit function selector
            calldata.push_str(&format!(
                "{:0>64}",
                format!("{:x}", amount1.parse::<u128>().unwrap())
            ));
            calldata.push_str(&format!(
                "{:0>64}",
                format!("{:x}", amount2.parse::<u128>().unwrap())
            ));
            calldata.push_str(&format!(
                "{:0>64}",
                l2_recipient1.strip_prefix("0x").unwrap_or(l2_recipient1)
            ));
            calldata.push_str(&format!(
                "{:0>64}",
                l2_recipient2.strip_prefix("0x").unwrap_or(l2_recipient2)
            ));

            let total_value = (amount1.parse::<u128>().unwrap()
                + amount2.parse::<u128>().unwrap()
                + 10000000000000000u128)
                .to_string();

            json!({
                "jsonrpc": "2.0",
                "method": "estimate_l1_to_l2_message_fees_from_unsigned_tx",
                "params": [{
                    "from": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", // Vitalik's address
                    "to": "0xEafC6a0b08f1AB67A00e618433C21de98358Bf5e", // DoubleDeposit contract
                    "value": total_value,
                    "data": calldata,
                    "gas": 300000,
                    "maxFeePerGas": "20000000000",      // 20 gwei
                    "maxPriorityFeePerGas": "20000000000" // 20 gwei
                }],
                "id": client_id * 1000 + request_id
            })
        }
    };

    let response = client
        .post(url)
        .header("Content-Type", "application/json")
        .timeout(Duration::from_secs(30)) // Longer timeout for transaction simulation
        .json(&request)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err("HTTP error".into());
    }

    let response_json: Value = response.json().await?;

    // Check if the response contains an error (including rate limit errors)
    if let Some(error_obj) = response_json.get("error") {
        let error_message = error_obj
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown error");
        let error_code = error_obj
            .get("code")
            .and_then(|c| c.as_str())
            .unwrap_or("unknown");

        // Log rate limit errors specifically
        if error_message.contains("Rate limit") || error_code.contains("rate_limit") {
            println!("⚠️  Rate limit error detected: {}", error_message);
        }

        return Err(format!("API error: {} ({})", error_message, error_code).into());
    }

    Ok(())
}
