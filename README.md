# Ethereum to Starknet Fee Estimation Server

A JSON-RPC server that processes Ethereum transactions, simulates them, extracts events, and estimates costs for corresponding Starknet operations.

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

#### `estimate_fee`

Estimates the cost of Starknet operations triggered by an Ethereum transaction.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "estimate_fee",
  "params": {
    "transaction": "0x...",
    "signed": true
  },
  "id": 1
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "status": "success",
    "message": "Fee estimation not yet implemented"
  },
  "id": 1
}
```

#### `simulate_transaction`

Simulates an Ethereum transaction and extracts relevant events.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "simulate_transaction",
  "params": {
    "transaction": "0x...",
    "signed": false
  },
  "id": 2
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "status": "success",
    "message": "Transaction simulation not yet implemented"
  },
  "id": 2
}
```

### Testing the API

```bash
# Test estimate_fee
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"estimate_fee","params":{"transaction":"0x123"},"id":1}' \
  http://127.0.0.1:8080

# Test simulate_transaction
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"simulate_transaction","params":{"transaction":"0x456"},"id":2}' \
  http://127.0.0.1:8080
```

## Architecture

- **Minimal main function**: Lean startup with configuration loading and server initialization
- **JSON-RPC interface**: Standard JSON-RPC 2.0 protocol for client communication
- **Configuration management**: Environment-based configuration for endpoints
- **Transaction Simulator**: Modular simulator for Ethereum transaction processing and fee estimation
- **Modular structure**: Organized code structure for future expansion

### Simulator Module

The transaction simulator (`src/simulator/`) provides:

- **Transaction Simulation**: Execute Ethereum transactions in a controlled environment
- **Fee Estimation**: Calculate gas costs and predict Starknet operation fees
- **Event Extraction**: Parse transaction logs and extract relevant events
- **Error Handling**: Comprehensive error types for different failure scenarios

The simulator is designed with placeholder implementations that can be filled in with the actual logic.

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
