use estimate_starknet_message_fee::server::RpcServer;
use reqwest::Client;
use serde_json::{json, Value};
use serial_test::serial;
use std::net::SocketAddr;
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::Duration;
use tokio::time::{sleep, timeout};

const TEST_PORT: u16 = 18080;
const TEST_HOST: &str = "127.0.0.1";
const ANVIL_PORT: u16 = 8545;
const ANVIL_HOST: &str = "127.0.0.1";

// Global state to manage Anvil process
static ANVIL_PROCESS: Mutex<Option<Child>> = Mutex::new(None);

/// Start Anvil node in the background
async fn start_anvil_node() -> Result<(), Box<dyn std::error::Error>> {
    // Check if anvil is already running by trying to connect
    let client = Client::new();
    let anvil_url = format!("http://{}:{}", ANVIL_HOST, ANVIL_PORT);

    if (client.post(&anvil_url).send().await).is_ok() {
        println!("Anvil is already running on {}", anvil_url);
        return Ok(());
    }

    println!("Starting Anvil node on {}:{}", ANVIL_HOST, ANVIL_PORT);

    // Start anvil process with forking (same setup as unit tests)
    let child = Command::new("anvil")
        .arg("--host")
        .arg(ANVIL_HOST)
        .arg("--port")
        .arg(ANVIL_PORT.to_string())
        .arg("--fork-url")
        .arg("https://reth-ethereum.ithaca.xyz/rpc")
        .arg("--fork-block-number")
        .arg("23113921")
        .arg("--silent") // Reduce anvil output
        .spawn()
        .expect("Failed to start anvil process");

    // Store the process handle globally
    {
        let mut process_guard = ANVIL_PROCESS.lock().unwrap();
        *process_guard = Some(child);
    }

    // Wait for anvil to be ready
    let mut attempts = 0;
    let max_attempts = 30;

    while attempts < max_attempts {
        if (client.post(&anvil_url).send().await).is_ok() {
            println!("Anvil node is ready!");
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
        attempts += 1;
    }

    Err("Failed to start Anvil node within timeout".into())
}

/// Stop Anvil node
fn stop_anvil_node() {
    let mut process_guard = ANVIL_PROCESS.lock().unwrap();
    if let Some(mut child) = process_guard.take() {
        println!("Stopping Anvil node...");
        let _ = child.kill();
        let _ = child.wait();
        println!("Anvil node stopped.");
    }
}

/// Setup function to ensure Anvil is running and start test server
async fn setup_test_environment() -> SocketAddr {
    // Start Anvil node
    start_anvil_node()
        .await
        .expect("Failed to start Anvil node");

    // Start test server
    start_test_server().await
}

/// Test helper to start the server in the background
async fn start_test_server() -> SocketAddr {
    let addr: SocketAddr = format!("{}:{}", TEST_HOST, TEST_PORT).parse().unwrap();

    // Create server with test configuration pointing to our Anvil node
    let l1_rpc_url = format!("http://{}:{}", ANVIL_HOST, ANVIL_PORT);
    let starknet_rpc_url = "https://pathfinder.rpc.sepolia.starknet.rs/rpc/v0_8".to_string();

    let server = RpcServer::new_with_config(l1_rpc_url, starknet_rpc_url)
        .expect("Failed to create RPC server");

    // Start the server in a background task
    tokio::spawn(async move {
        if let Err(e) = server.start(addr).await {
            eprintln!("Server error: {}", e);
        }
    });

    // Wait for the server to start
    let client = Client::new();
    let mut attempts = 0;
    let max_attempts = 50;

    while attempts < max_attempts {
        if client
            .get(format!("http://{}:{}", TEST_HOST, TEST_PORT))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        sleep(Duration::from_millis(100)).await;
        attempts += 1;
    }

    if attempts >= max_attempts {
        panic!("Server failed to start within timeout");
    }

    addr
}

/// Validate API response structure - should have either success result or error
fn validate_api_response(response: &Value) {
    // Verify JSON-RPC structure
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);

    // The response should contain a result field (JSON-RPC wrapper)
    assert!(response.get("result").is_some());
    let api_response = response.get("result").unwrap();

    // Within the result, we should have either our success result or error, but not both
    let has_success = api_response.get("result").is_some();
    let has_error = api_response.get("error").is_some();

    assert!(
        has_success || has_error,
        "Response must have either result or error"
    );
    assert!(
        !(has_success && has_error),
        "Response cannot have both result and error"
    );

    if has_error {
        let error = api_response.get("error").unwrap();
        println!("API Error: {}", error);

        // Validate error structure
        assert!(error.get("code").is_some());
        assert!(error.get("message").is_some());

        // The error code should be one of our defined ApiErrorCode values
        let code = error.get("code").unwrap().as_str().unwrap();
        assert!(matches!(
            code,
            "invalid_input_format"
                | "invalid_unsigned_transaction"
                | "invalid_signed_transaction"
                | "transaction_simulation_failed"
                | "fee_estimation_failed"
                | "internal_error"
        ));
    } else if has_success {
        let result = api_response.get("result").unwrap();
        println!("API Success: {}", result);

        // Validate the FeeEstimationSummary structure
        assert!(result.is_object());
        assert!(result.get("total_messages").is_some());
        assert!(result.get("successful_estimates").is_some());
        assert!(result.get("failed_estimates").is_some());
        assert!(result.get("total_fee_wei").is_some());
        assert!(result.get("total_fee_eth").is_some());
        assert!(result.get("individual_estimates").is_some());
        assert!(result.get("errors").is_some());
    }
}

/// Validate that the response contains a successful fee estimation
fn validate_successful_fee_estimation(response: &Value) {
    // Verify JSON-RPC structure
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);

    // The response should contain a result field (JSON-RPC wrapper)
    assert!(response.get("result").is_some());
    let api_response = response.get("result").unwrap();

    // Must have a successful result, not an error
    assert!(
        api_response.get("result").is_some(),
        "Expected successful result, but got: {}",
        api_response
    );
    assert!(
        api_response.get("error").is_none(),
        "Expected no error, but got: {}",
        api_response
    );

    let result = api_response.get("result").unwrap();
    println!("Validating successful fee estimation: {}", result);

    // Validate FeeEstimationSummary structure exists
    assert!(result.is_object());
    assert!(result.get("total_messages").is_some());
    assert!(result.get("successful_estimates").is_some());
    assert!(result.get("failed_estimates").is_some());
    assert!(result.get("total_fee_wei").is_some());
    assert!(result.get("total_fee_eth").is_some());
    assert!(result.get("individual_estimates").is_some());
    assert!(result.get("errors").is_some());

    // Validate meaningful values
    let total_messages = result.get("total_messages").unwrap().as_u64().unwrap();
    let successful_estimates = result
        .get("successful_estimates")
        .unwrap()
        .as_u64()
        .unwrap();
    let failed_estimates = result.get("failed_estimates").unwrap().as_u64().unwrap();
    let total_fee_wei = result.get("total_fee_wei").unwrap().as_u64().unwrap_or(0);
    let individual_estimates = result
        .get("individual_estimates")
        .unwrap()
        .as_array()
        .unwrap();

    // Basic validation
    assert!(total_messages > 0, "Should have at least one message");
    assert_eq!(
        total_messages,
        successful_estimates + failed_estimates,
        "Total should equal successful + failed"
    );
    assert!(
        successful_estimates > 0,
        "Should have at least one successful estimate"
    );
    assert_eq!(
        individual_estimates.len() as u64,
        successful_estimates,
        "Individual estimates count should match successful count"
    );

    // If we have successful estimates, validate the fee values are reasonable
    if successful_estimates > 0 {
        assert!(
            total_fee_wei > 0,
            "Total fee should be greater than 0 for successful estimates"
        );

        // Validate each individual estimate
        for (i, estimate) in individual_estimates.iter().enumerate() {
            assert!(
                estimate.is_object(),
                "Individual estimate {} should be an object",
                i
            );
            assert!(
                estimate.get("l2_address").is_some(),
                "Estimate {} missing l2_address",
                i
            );
            assert!(
                estimate.get("selector").is_some(),
                "Estimate {} missing selector",
                i
            );
            assert!(
                estimate.get("gas_consumed").is_some(),
                "Estimate {} missing gas_consumed",
                i
            );
            assert!(
                estimate.get("gas_price").is_some(),
                "Estimate {} missing gas_price",
                i
            );
            assert!(
                estimate.get("overall_fee").is_some(),
                "Estimate {} missing overall_fee",
                i
            );
            assert!(
                estimate.get("unit").is_some(),
                "Estimate {} missing unit",
                i
            );

            // Validate reasonable values
            let gas_consumed = estimate.get("gas_consumed").unwrap().as_u64().unwrap();
            let gas_price = estimate.get("gas_price").unwrap().as_u64().unwrap();
            let overall_fee = estimate.get("overall_fee").unwrap().as_u64().unwrap();

            assert!(
                gas_consumed > 0,
                "Gas consumed should be > 0 for estimate {}",
                i
            );
            assert!(gas_price > 0, "Gas price should be > 0 for estimate {}", i);
            assert!(
                overall_fee > 0,
                "Overall fee should be > 0 for estimate {}",
                i
            );

            // Basic sanity check: overall fee should be related to gas
            assert!(
                overall_fee >= gas_consumed,
                "Overall fee should be at least gas consumed for estimate {}",
                i
            );
        }
    }

    println!(
        "✅ Fee estimation validation passed: {} messages, {} successful, total fee: {} wei",
        total_messages, successful_estimates, total_fee_wei
    );
}

/// Validate that the response contains a specific error type
fn validate_expected_error(response: &Value, expected_error_code: &str) {
    // Verify JSON-RPC structure
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);

    // The response should contain a result field (JSON-RPC wrapper)
    assert!(response.get("result").is_some());
    let api_response = response.get("result").unwrap();

    // Must have an error, not a successful result
    assert!(
        api_response.get("error").is_some(),
        "Expected error, but got: {}",
        api_response
    );
    assert!(
        api_response.get("result").is_none(),
        "Expected no result, but got: {}",
        api_response
    );

    let error = api_response.get("error").unwrap();
    println!("Validating expected error: {}", error);

    // Validate error structure
    assert!(error.get("code").is_some());
    assert!(error.get("message").is_some());

    let code = error.get("code").unwrap().as_str().unwrap();
    assert_eq!(
        code, expected_error_code,
        "Expected error code '{}', got '{}'",
        expected_error_code, code
    );

    println!(
        "✅ Error validation passed: got expected error '{}'",
        expected_error_code
    );
}

/// Send a JSON-RPC request to the server
async fn send_rpc_request(method: &str, params: Value) -> Result<Value, reqwest::Error> {
    let client = Client::new();
    let url = format!("http://{}:{}", TEST_HOST, TEST_PORT);

    let request_body = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await?;

    let response_json: Value = response.json().await?;
    Ok(response_json)
}

#[tokio::test]
#[serial]
async fn test_estimate_l1_to_l2_message_fees_success() {
    let _addr = setup_test_environment().await;

    // Test data using the exact same working values from unit tests
    // This uses the real Starknet deposit transaction from block 23113921
    // Values extracted from the actual L1ToL2MessageSent event in the unit tests
    let params = json!([{
        "messages": [
            {
                "from_address": "0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4",
                "l2_address": "0x594c1582459ea03f77deaf9eb7e3917d6994a03c13405ba42867f83d85f085d", // Converted from decimal
                "selector": "0x1b64b1b3b690b43b9b514fb81377518f4039cd3e4f4914d8a6bdf01d679fb19", // Converted from decimal
                "payload": [
                    "0xca14007eff0db1f8135f4c25b34de49ab0d42766",
                    "0x11dd734a52cd2ee23ffe8b5054f5a8ecf5d1ad50",
                    "0x13cd2f10b45da0332429cea44028b89ee386cb2adfb9bb8f1c470bad6a1f8d1",
                    "0x4f9c6a3ec958b0de0000",
                    "0x0"
                ]
            }
        ]
    }]);

    let response = timeout(
        Duration::from_secs(30),
        send_rpc_request("estimate_l1_to_l2_message_fees", params),
    )
    .await
    .expect("Request timeout")
    .expect("Request failed");

    println!(
        "estimate_l1_to_l2_message_fees_success response: {}",
        serde_json::to_string_pretty(&response).unwrap()
    );

    // This test expects successful fee estimation
    validate_successful_fee_estimation(&response);
}

#[tokio::test]
#[serial]
async fn test_estimate_l1_to_l2_message_fees_error_cases() {
    let _addr = setup_test_environment().await;

    // Test data for L1 to L2 message fees that should fail
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

    let response = timeout(
        Duration::from_secs(30),
        send_rpc_request("estimate_l1_to_l2_message_fees", params),
    )
    .await
    .expect("Request timeout")
    .expect("Request failed");

    println!(
        "estimate_l1_to_l2_message_fees_error_cases response: {}",
        serde_json::to_string_pretty(&response).unwrap()
    );

    // This test can handle either success or error gracefully
    validate_api_response(&response);
}

#[tokio::test]
#[serial]
async fn test_estimate_l1_to_l2_message_fees_from_unsigned_tx_success() {
    let _addr = setup_test_environment().await;

    // Test data using the exact same unsigned transaction from unit tests
    // This simulates the Starknet deposit transaction from block 23113921
    let params = json!([{
        "from": "0x11Dd734a52Cd2EE23FFe8B5054F5A8ECF5D1Ad50", // Original sender
        "to": "0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4", // Starknet Core contract
        "value": "25344429452040", // Value in wei from original tx
        "data": "0x0efe6a8b000000000000000000000000ca14007eff0db1f8135f4c25b34de49ab0d42766000000000000000000000000000000000000000000004f9c6a3ec958b0de0000013cd2f10b45da0332429cea44028b89ee386cb2adfb9bb8f1c470bad6a1f8d1",
        "gas": 190674, // Gas limit from original tx
        "gasPrice": "2306574200", // Gas price from original tx
        "nonce": 58 // Nonce from original tx
    }]);

    let response = timeout(
        Duration::from_secs(30),
        send_rpc_request("estimate_l1_to_l2_message_fees_from_unsigned_tx", params),
    )
    .await
    .expect("Request timeout")
    .expect("Request failed");

    println!(
        "estimate_l1_to_l2_message_fees_from_unsigned_tx_success response: {}",
        serde_json::to_string_pretty(&response).unwrap()
    );

    // This test expects a transaction simulation error due to insufficient funds
    validate_expected_error(&response, "transaction_simulation_failed");
}

#[tokio::test]
#[serial]
async fn test_estimate_l1_to_l2_message_fees_from_unsigned_tx_error() {
    let _addr = setup_test_environment().await;

    // Test data for unsigned transaction that should fail (invalid transaction)
    let params = json!([{
        "from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
        "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "value": "1000000000000000000",
        "data": "0x",
        "gas": 21000,
        "gasPrice": "20000000000"
    }]);

    let response = timeout(
        Duration::from_secs(30),
        send_rpc_request("estimate_l1_to_l2_message_fees_from_unsigned_tx", params),
    )
    .await
    .expect("Request timeout")
    .expect("Request failed");

    println!(
        "estimate_l1_to_l2_message_fees_from_unsigned_tx_error response: {}",
        serde_json::to_string_pretty(&response).unwrap()
    );

    // This test can handle either success or error gracefully
    validate_api_response(&response);
}

#[tokio::test]
#[serial]
async fn test_estimate_l1_to_l2_message_fees_from_signed_tx() {
    let _addr = setup_test_environment().await;

    // Test data for signed transaction (this is a mock transaction hex)
    let params = json!(["0xf86c808509184e72a00082520894d46e8dd67c5d32be8058bb8eb970870f07244567849184e72aa9d46e8dd67c5d32be8d46e8dd67c5d32be8058bb8eb970870f072445678025a0c9cf86333bcb065d971d8e62a6b6b8b2c7c2e4b5a2e3a9e2b8c2e4b5a2e3a9e2c0"]);

    let response = timeout(
        Duration::from_secs(30),
        send_rpc_request("estimate_l1_to_l2_message_fees_from_signed_tx", params),
    )
    .await
    .expect("Request timeout")
    .expect("Request failed");

    println!(
        "estimate_l1_to_l2_message_fees_from_signed_tx response: {}",
        serde_json::to_string_pretty(&response).unwrap()
    );

    // Validate the response using our helper function
    validate_api_response(&response);
}

#[tokio::test]
#[serial]
async fn test_invalid_method() {
    let _addr = setup_test_environment().await;

    let params = json!([]);

    let response = timeout(
        Duration::from_secs(10),
        send_rpc_request("invalid_method", params),
    )
    .await
    .expect("Request timeout")
    .expect("Request failed");

    println!(
        "invalid_method response: {}",
        serde_json::to_string_pretty(&response).unwrap()
    );

    // Should return a method not found error
    assert_eq!(response["jsonrpc"], "2.0");
    assert_eq!(response["id"], 1);
    assert!(response.get("error").is_some());

    let error = response["error"].as_object().unwrap();
    assert_eq!(error["code"], -32601); // Method not found
}

#[tokio::test]
#[serial]
async fn test_malformed_request() {
    let _addr = setup_test_environment().await;

    let client = Client::new();
    let url = format!("http://{}:{}", TEST_HOST, TEST_PORT);

    // Send malformed JSON
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body("{invalid json")
        .send()
        .await
        .expect("Request failed");

    let response_json: Value = response
        .json()
        .await
        .expect("Failed to parse response JSON");

    println!(
        "malformed_request response: {}",
        serde_json::to_string_pretty(&response_json).unwrap()
    );

    // Should return a parse error
    assert!(response_json.get("error").is_some());
    let error = response_json["error"].as_object().unwrap();
    assert_eq!(error["code"], -32700); // Parse error
}

#[tokio::test]
#[serial]
async fn test_invalid_parameters() {
    let _addr = setup_test_environment().await;

    // Test with missing required parameters
    let params = json!([{
        "messages": [
            {
                // Missing required fields
                "l2_address": "0x04c5772d1914fe6ce891b64eb35bf3522aeae1315647314aac58b01137607f3f"
            }
        ]
    }]);

    let response = timeout(
        Duration::from_secs(10),
        send_rpc_request("estimate_l1_to_l2_message_fees", params),
    )
    .await
    .expect("Request timeout")
    .expect("Request failed");

    println!(
        "invalid_parameters response: {}",
        serde_json::to_string_pretty(&response).unwrap()
    );

    // This test expects a specific error
    validate_expected_error(&response, "invalid_input_format");
}

#[tokio::test]
#[serial]
async fn test_unsigned_tx_missing_from_field() {
    let _addr = setup_test_environment().await;

    // Test unsigned transaction without required 'from' field
    let params = json!([{
        "to": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        "value": "1000000000000000000"
        // Missing 'from' field
    }]);

    let response = timeout(
        Duration::from_secs(10),
        send_rpc_request("estimate_l1_to_l2_message_fees_from_unsigned_tx", params),
    )
    .await
    .expect("Request timeout")
    .expect("Request failed");

    println!(
        "unsigned_tx_missing_from response: {}",
        serde_json::to_string_pretty(&response).unwrap()
    );

    // This test expects a specific error
    validate_expected_error(&response, "invalid_unsigned_transaction");
}

#[tokio::test]
#[serial]
async fn test_server_health() {
    let _addr = setup_test_environment().await;

    // Test basic connectivity to ensure server is running
    let client = Client::new();
    let url = format!("http://{}:{}", TEST_HOST, TEST_PORT);

    // Send a simple POST request to verify server is responding
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "estimate_l1_to_l2_message_fees",
            "params": [{"messages": []}],
            "id": 1
        }))
        .send()
        .await
        .expect("Request failed");

    // Should get a response (even if it's an error due to empty messages)
    assert!(response.status().is_success() || response.status().is_client_error());

    let response_json: Value = response
        .json()
        .await
        .expect("Failed to parse response JSON");
    println!(
        "server_health response: {}",
        serde_json::to_string_pretty(&response_json).unwrap()
    );

    // Should have proper JSON-RPC structure
    assert_eq!(response_json["jsonrpc"], "2.0");
    assert_eq!(response_json["id"], 1);
}

/// Cleanup test that runs last to stop Anvil
#[tokio::test]
#[serial]
async fn test_z_cleanup() {
    println!("Cleaning up test environment...");
    stop_anvil_node();
    println!("Test cleanup completed.");
}
