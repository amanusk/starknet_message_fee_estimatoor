# Starknet Message Fee Estimation Server

A JSON-RPC server that enables accurate fee estimation for L1-to-L2 message passing between Ethereum and Starknet.

## Why?

Starknet supports message from L1 to L1 handlers. These are handles like other Starknet transactions, but payment for them is done on L1. So far there has not been an easy way to know how much should an L1-to-L2 message cost.

Starknet API does support and EstimateMessageFee endpoint, but it requires to know the structure of the message being sent, and it is not trivial to dynamically parse it from the L1 transaction. This is what this server does.

## What it does

This server provides the following capabilities:

1. Directly estimate a L1toL2 Message if all the information is know

2. Estimating fees from L1 transactions

- Simulate the signed/unsigned transaction
- Extract its L1toL2 events
- Estimate the total cost of the L1 and L2 messages

## Quick Start

### Running the Server

```bash
cargo run
```

The server will start on `http://127.0.0.1:8080` by default.

### Configuration

The server supports multiple configuration methods, applied in this order of priority:

1. **Default values** (built-in)
2. **Configuration file** (`config.toml`)
3. **Environment variables** (highest priority)

#### Configuration File

Copy the example configuration file and modify it:

```bash
cp config.example.toml config.toml
# Edit config.toml with your preferred settings
```

**Note:** The `config.toml` file is ignored by git to prevent accidentally committing sensitive configuration data.

#### Environment Variables

You can override any configuration using environment variables with the `APP_` prefix:

```bash
export APP_SERVER_HOST=127.0.0.1
export APP_SERVER_PORT=8080
export APP_ETHEREUM_ENDPOINT=http://localhost:8545
export APP_STARKNET_ENDPOINT=https://starknet-mainnet.public.blastapi.io
```

#### Configuration Options

| Setting             | Default                                       | Description           |
| ------------------- | --------------------------------------------- | --------------------- |
| `server.host`       | `127.0.0.1`                                   | Server bind address   |
| `server.port`       | `8080`                                        | Server port           |
| `ethereum.endpoint` | `http://localhost:8545`                       | Ethereum RPC endpoint |
| `starknet.endpoint` | `https://starknet-mainnet.public.blastapi.io` | Starknet RPC endpoint |

## JSON-RPC API

### Available Methods

The server provides three main JSON-RPC methods for fee estimation:

1. **`estimate_l1_to_l2_message_fees`** - Estimates fees for L1 to L2 message events directly
2. **`estimate_l1_to_l2_message_fees_from_unsigned_tx`** - Estimates fees by simulating an unsigned Ethereum transaction
3. **`estimate_l1_to_l2_message_fees_from_signed_tx`** - Estimates fees by simulating a signed Ethereum transaction

### API Documentation and Examples

For detailed API documentation, request/response formats, and working examples, see:

- **[API Examples](examples/estimate_fees_example.md)** - Complete API documentation with request/response examples
- **[Client Example](examples/client_example.rs)** - Rust client implementation

### Quick Test

Test the server with a simple curl command:

## Examples and Testing

### Running Examples

The project includes several examples to demonstrate usage:

```bash
# Run the client example (requires server to be running)
cargo run --example client_example
```

### Running Tests

Run the integration tests to verify the server functionality:

```bash
# Run all tests
cargo test

# Run only integration tests
cargo test --test integration_tests

# Run tests with output
cargo test -- --nocapture
```

The integration tests will:

- Start the server automatically
- Test all API endpoints
- Verify error handling
- Check response formats

### Core Components

- **JSON-RPC Server** (`src/server/`): Standard JSON-RPC 2.0 protocol handling with multiple endpoint support
- **Transaction Simulator** (`src/simulator/`): Ethereum transaction execution and L1-to-L2 event extraction
- **Fee Estimator** (`src/fee_estimator/`): Starknet RPC integration for accurate fee calculation
- **Configuration Management** (`src/config/`): Flexible configuration via files and environment variables

### Processing Flow

1. **Request Routing**: The JSON-RPC server receives requests and routes them based on method type
2. **Transaction Processing**: Depending on the request type:
   - Direct messages are validated and passed through
   - Unsigned transactions are simulated using account impersonation
   - Signed transactions are parsed and simulated
3. **Event Extraction**: L1-to-L2 message events are extracted from transaction logs
4. **Fee Estimation**: Each message is sent to Starknet's RPC for accurate fee calculation
5. **Response Assembly**: Results are aggregated and returned as a comprehensive fee estimate

## Next Steps

- [x] Implement Ethereum transaction parsing and simulation
- [x] Add event extraction from simulation results
- [x] Integrate Starknet client for fee estimation
- [ ] Add proper error handling and validation
- [ ] Implement logging and monitoring
- [ ] Set a simplified API and test it
- [ ] Set possible errors returned from the server
- [ ] Publish as a crate and library
- [ ] More test coverage for possible failures and edge cases
- [ ] Run benchmarks and stress tests
