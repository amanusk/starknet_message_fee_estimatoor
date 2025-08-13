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
    "result": {
      "errors": [],
      "failed_estimates": 0,
      "individual_estimates": [
        {
          "gas_consumed": 20180,
          "gas_price": 6381820900,
          "l2_address": "0x594c1582459ea03f77deaf9eb7e3917d6994a03c13405ba42867f83d85f085d",
          "overall_fee": 128785145762192,
          "selector": "0x1b64b1b3b690b43b9b514fb81377518f4039cd3e4f4914d8a6bdf01d679fb19",
          "unit": "Wei"
        }
      ],
      "successful_estimates": 1,
      "total_fee_eth": 0.000128785145762192,
      "total_fee_wei": 128785145762192,
      "total_messages": 1
    }
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
      }
    ],
    "id": 1
}'
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

## Unsigned Transaction Simulation

The library also provides functionality to simulate unsigned transactions using account impersonation. This is useful for testing and gas estimation without needing private keys.
