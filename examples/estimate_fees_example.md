# Starknet Message Fee Estimation API

This service provides RPC endpoints to estimate fees for L1 to L2 messages using Starknet RPC.

## Configuration

The service can be configured via a `config.toml` file or environment variables:

```toml
[server]
host = "127.0.0.1"
port = 8080

[ethereum]
endpoint = "https://eth-mainnet.public.blastapi.io"

[starknet]
endpoint = "https://starknet-mainnet.public.blastapi.io"
```

Environment variables (with `APP_` prefix):

- `APP_SERVER_HOST=127.0.0.1`
- `APP_SERVER_PORT=8080`
- `APP_ETHEREUM_ENDPOINT=https://eth-mainnet.public.blastapi.io` (for L1 transaction simulation)
- `APP_STARKNET_ENDPOINT=https://starknet-mainnet.public.blastapi.io` (for fee estimation)

## RPC Endpoint

### `estimate_l1_to_l2_message_fees`

Estimates fees for a list of L1 to L2 message events.

**Request Format:**

```json
{
  "jsonrpc": "2.0",
  "method": "estimate_l1_to_l2_message_fees",
  "params": [
    {
      "messages": [
        {
          "l2_address": "0x059dac5df32cbce17b081399e97d90be5fba726f97f00638f838613d088e5a47",
          "selector": "0x01b755de86a18a8a0d2b5a4b0b2f40c3c584c2e45df20e8c0de5db20a6c4fb7",
          "payload": [
            "0xca14007eff0db1f8135f4c25b34de49ab0d42766",
            "0x11dd734a52cd2ee23ffe8b5054f5a8ecf5d1ad50",
            "0x13cd2f10b45da0332429cea44028b89ee386cb2adfb9bb8f1c470bad6a1f8d1",
            "0x4f9c6a3ec958b0de0000",
            "0x0"
          ]
        }
      ]
    }
  ],
  "id": 1
}
```

**Response Format:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "total_messages": 1,
    "successful_estimates": 1,
    "failed_estimates": 0,
    "total_fee_wei": 123456789000000,
    "total_fee_eth": 0.000123456789,
    "individual_estimates": [
      {
        "l2_address": "0x059dac5df32cbce17b081399e97d90be5fba726f97f00638f838613d088e5a47",
        "selector": "0x01b755de86a18a8a0d2b5a4b0b2f40c3c584c2e45df20e8c0de5db20a6c4fb7",
        "gas_consumed": 123456,
        "gas_price": 1000000000,
        "overall_fee": 123456789000000,
        "unit": "Wei"
      }
    ],
    "errors": []
  },
  "id": 1
}
```

## Example Usage

### Using curl

```bash
curl -X POST http://localhost:8080 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "estimate_l1_to_l2_message_fees",
    "params": [
      {
        "messages": [
          {
            "l2_address": "0x059dac5df32cbce17b081399e97d90be5fba726f97f00638f838613d088e5a47",
            "selector": "0x01b755de86a18a8a0d2b5a4b0b2f40c3c584c2e45df20e8c0de5db20a6c4fb7",
            "payload": [
              "0xca14007eff0db1f8135f4c25b34de49ab0d42766",
              "0x4f9c6a3ec958b0de0000"
            ]
          }
        ]
      }
    ],
    "id": 1
  }'
```

### Using JavaScript/Node.js

```javascript
const response = await fetch("http://localhost:8080", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    jsonrpc: "2.0",
    method: "estimate_l1_to_l2_message_fees",
    params: [
      {
        messages: [
          {
            l2_address:
              "0x059dac5df32cbce17b081399e97d90be5fba726f97f00638f838613d088e5a47",
            selector:
              "0x01b755de86a18a8a0d2b5a4b0b2f40c3c584c2e45df20e8c0de5db20a6c4fb7",
            payload: [
              "0xca14007eff0db1f8135f4c25b34de49ab0d42766",
              "0x4f9c6a3ec958b0de0000",
            ],
          },
        ],
      },
    ],
    id: 1,
  }),
});

const result = await response.json();
console.log("Fee estimation result:", result.result);
```

## Response Fields

- **total_messages**: Total number of messages provided for estimation
- **successful_estimates**: Number of messages that were successfully estimated
- **failed_estimates**: Number of messages that failed to estimate
- **total_fee_wei**: Total estimated fee in Wei for all successful messages
- **total_fee_eth**: Total estimated fee in ETH (converted from Wei)
- **individual_estimates**: Array of individual fee estimates for each message
- **errors**: Array of error messages for failed estimations

Each individual estimate contains:

- **l2_address**: The L2 contract address
- **selector**: The function selector to call
- **gas_consumed**: Gas consumed for the message
- **gas_price**: Gas price used for the estimate
- **overall_fee**: Total fee for this specific message
- **unit**: The unit of the fee (typically "Wei")

## Running the Service

```bash
# Build the project
cargo build --release

# Run with default configuration
cargo run

# Run with custom environment variables
APP_STARKNET_ENDPOINT=https://your-starknet-rpc.com cargo run
```

The service will start on `http://127.0.0.1:8080` by default.
