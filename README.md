# BaseStamp Go Client Library & CLI

BaseStamp is a cryptographic timestamping service that anchors file hashes to the blockchain, providing immutable proof of when your files existed. This repository contains the official Go client library and command-line interface.

## Features

- **Go Client Library**: Easy-to-use API similar to the Python client
- **Command-Line Interface**: Simple CLI tool for timestamping files
- **Blockchain Verification**: Trustless verification using Merkle proofs and direct JSON-RPC checks of the Basestamp contract
- **Privacy Protection**: Uses nonces to protect file contents
- **Networks**: Base mainnet (default, chain 8453) and Base Sepolia testnet

## Installation

### Go Install

```bash  
go install github.com/basestamp/basestamp-go/cmd/basestamp@latest
```

### Download Binary

Download the latest release from [GitHub Releases](https://github.com/basestamp/basestamp-go/releases).

## CLI Usage

### Stamping a File

```bash
# Stamp a file (creates document.pdf.basestamp proof file)
basestamp stamp document.pdf

# Stamp with custom output file
basestamp stamp document.pdf --output document.stamp

# Stamp with verbose output
basestamp stamp document.pdf --verbose
```

### Stamping a Hash

```bash
# Example hash (SHA256 of empty string)
HASH="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Stamp a hash directly (outputs JSON to stdout)
basestamp stamp --hash $HASH

# Stamp a hash from stdin (outputs JSON to stdout)
echo "$HASH" | basestamp stamp

# Save hash stamp JSON to file
basestamp stamp --hash $HASH > proof.json

# Hash mode with verbose status (status goes to stderr, JSON to stdout)
basestamp stamp --hash $HASH --verbose
```

### Verifying a File

```bash
# Verify a file against its proof
basestamp verify document.pdf

# Verify against a specific proof file
basestamp verify document.pdf document.stamp

# Verify with detailed output
basestamp verify document.pdf --verbose
```

### Verifying a Hash

```bash
# Example hash (SHA256 of empty string)  
HASH="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Verify a hash against a stamp file
basestamp verify --hash $HASH document.stamp

# Verify a hash against stamp JSON from stdin (pipe from stamp command)
basestamp stamp --hash $HASH 2>/dev/null | basestamp verify --hash $HASH

# Verify with verbose debugging output
basestamp verify --hash $HASH document.stamp --verbose

# Complete workflow: stamp and verify a hash
basestamp stamp --hash $HASH > proof.json 2>/dev/null
cat proof.json | basestamp verify --hash $HASH
```

### Getting Help

```bash
# Show help
basestamp --help
```

## Go Library Usage

### Installation

```bash
go get github.com/basestamp/basestamp-go
```

### Basic Usage

```go
package main

import (
    "fmt"
    "log"
    "github.com/basestamp/basestamp-go"
)

func main() {
    // Initialize the client
    client := basestamp.NewClient()
    
    // Calculate hash of your data
    hash := basestamp.CalculateSHA256("Hello, BaseStamp!")
    
    // Submit hash for timestamping
    stampID, err := client.SubmitSHA256(hash)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Stamp ID: %s\n", stampID)
    
    // Get the stamp with proof (wait for blockchain confirmation)
    stamp, err := client.GetStamp(stampID, nil) // Use defaults (Wait: true)
    if err != nil {
        log.Fatal(err)
    }
    
    // Verify the stamp: leaf binding, merkle path and on-chain anchor
    valid, err := stamp.Verify(hash)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Stamp is valid: %v\n", valid)
    
    // Get additional information
    stampedAt, _ := stamp.GetStampedAt()
    fmt.Printf("Stamped at: %v\n", stampedAt)
}
```

### Advanced Usage

```go
// Use custom API URL
client := basestamp.NewClientWithURL("https://your-basestamp-server.com")

// Calculate hash from bytes
data := []byte("Some binary data")
hash := basestamp.CalculateSHA256Bytes(data)

// Get stamp without waiting
stamp, err := client.GetStamp(stampID, basestamp.NoWait())

// Access raw API response
rawResponse := stamp.GetRawResponse()

// Get blockchain information
blockchainInfo, err := stamp.GetBlockchainInfo()

// Detailed verification (block number, timestamp, confirmations)
res, err := stamp.VerifyDetailed(ctx, hash)
fmt.Println(res.Anchor.BlockNumber, res.Anchor.BlockTimestamp, res.TxID)

// Merkle-only check (no network; does NOT prove on-chain anchoring)
ok, err := stamp.VerifyOffline(hash)

// Verify a saved API response later
var saved map[string]interface{} // GET /stamp/{id} JSON
res, err = basestamp.NewStampFromResponse(nil, saved).VerifyDetailed(ctx, hash)

// Use your own RPC endpoint (verification stays pinned to Base mainnet)
cfg := blockchain.Mainnet
cfg.RPCURL = "https://your-base-rpc.example"
client = basestamp.NewClient().WithChain(cfg)
```

## API Reference

### Client Methods

- `NewClient()` - Create client with default API URL
- `NewClientWithURL(url)` - Create client with custom API URL (verification pinned to mainnet unless `url` is `SepoliaAPIURL`)
- `WithChain(cfg)` - Choose the deployment (`blockchain.Mainnet`, `blockchain.Sepolia`, custom RPC) for on-chain verification
- `SubmitSHA256(hash)` / `SubmitSHA256Context(ctx, hash)` - Submit a 64-hex-char hash (normalized to lowercase)
- `GetStamp(stampID, opts)` - Get stamp with configurable options

### Stamp Methods

- `Verify(hash)` - Full verification (leaf binding + merkle path + on-chain anchor). Returns
  `(false, nil)` if `hash` is not this stamp's hash and `(false, err)` for any other failure
  (`errors.Is(err, basestamp.ErrInvalidProof)`, `errors.Is(err, blockchain.ErrNotAnchored)`)
- `VerifyDetailed(ctx, hash)` - Same checks, returns `*VerificationResult` with the on-chain `Anchor`
- `VerifyOffline(hash)` - Leaf binding + merkle path only (no network)
- `GetHash()` - Get the submitted hash
- `GetNonce()`, `GetTxID()`, `GetMerkleRoot()`, `GetStatus()` - Response fields
- `GetStampedAt()` - Get the stamp time
- `GetBlockchainInfo()` - Get blockchain transaction info
- `GetRawResponse()` - Get raw API response

### GetStampOptions

Configure the behavior of `GetStamp` requests:

```go
type GetStampOptions struct {
    Wait        *bool          // Poll until merkle proof is available (nil = default: true)
    MaxAttempts int            // Maximum polling attempts (default: 30) 
    RetryDelay  time.Duration  // Delay between attempts (default: 2s)
    Context     context.Context // For cancellation (default: context.Background())
}
```

Examples:
```go
// Use defaults (Wait: true, MaxAttempts: 30, RetryDelay: 2s)
stamp, err := client.GetStamp(stampID, nil)

// Don't wait, return immediately
stamp, err := client.GetStamp(stampID, basestamp.NoWait())

// Explicit waiting (same as nil)
stamp, err := client.GetStamp(stampID, &basestamp.GetStampOptions{Wait: basestamp.BoolPtr(true)})

// Wait with custom timing
stamp, err := client.GetStamp(stampID, &basestamp.GetStampOptions{
    MaxAttempts: 60,
    RetryDelay: time.Second,
})

// With context cancellation
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
defer cancel()
stamp, err := client.GetStamp(stampID, &basestamp.GetStampOptions{Context: ctx})
```

### File Operations

For working with files directly:

```go
// Create a FileStamp from a file
fileStamp, err := basestamp.CreateFileStamp("document.pdf")

// Save FileStamp to disk  
err = basestamp.SaveFileStamp(fileStamp, "document.pdf.basestamp")

// Load FileStamp from disk
loadedStamp, err := basestamp.LoadFileStamp("document.pdf.basestamp")

// Verify file against its stamp file (local file/nonce check only)
valid, err := basestamp.VerifyFileStamp("document.pdf", "document.pdf.basestamp")

// Verify file, stored merkle proof and on-chain anchor
res, err := basestamp.VerifyFileStampProof(ctx, "document.pdf", "document.pdf.basestamp", nil)

// Calculate file hash directly
hash, err := basestamp.CalculateFileHash("document.pdf")

// Work with privacy-preserving stamped hashes
stampedHash, err := basestamp.CreateStampedHash("document.pdf")
err = basestamp.VerifyStampedHash("document.pdf", stampedHash)
```

### Utility Functions

- `CalculateSHA256(data)` - Calculate SHA256 of string
- `CalculateSHA256Bytes(data)` - Calculate SHA256 of bytes
- `CalculateFileHash(filename)` - Calculate SHA256 of file
- `CreateFileStamp(filename)` - Create FileStamp from file
- `LoadFileStamp(filename)` - Load FileStamp from JSON file
- `SaveFileStamp(stamp, filename)` - Save FileStamp to JSON file
- `VerifyFileStamp(filename, stampFile)` - Verify file against stamp
- `CreateStampedHash(filename)` - Create stamped hash with nonce
- `VerifyStampedHash(filename, stampedHash)` - Verify stamped hash
- `BoolPtr(b)` - Helper to create *bool for GetStampOptions.Wait
- `NoWait()` - Returns GetStampOptions configured to not wait

## Development

### Building

```bash
go build ./cmd/basestamp
```

### Running Tests

```bash
go test ./...

# Re-verify the real mainnet vectors against Base RPC (read-only, free)
BASESTAMP_ONLINE=1 go test -run TestOnChainVectors -v .

# End-to-end on Base mainnet: stamps ONE random hash (costs the service real ETH)
BASESTAMP_E2E=1 go test -run TestE2EMainnet -v -timeout 20m .
```

`testdata/vectors.json` holds cross-SDK test vectors shared with
basestamp-ts and basestamp-python (real mainnet proofs plus tampered cases).

### Releasing

This project uses [GoReleaser](https://goreleaser.com/) for automated releases:

```bash
# Create a git tag
git tag v1.0.0
git push origin v1.0.0

# GoReleaser will automatically build and release
```

## Configuration

The CLI uses the following configuration:

- **Server URL**: Default is `https://api-mainnet.basestamp.io` (Base mainnet, chain 8453). For Base Sepolia testnet use `--server https://api-sepolia.basestamp.io` or `basestamp.NewClientWithURL(basestamp.SepoliaAPIURL)`
- **Config File**: `~/.basestamp.yaml` (optional)
- **Environment Variables**: 
  - `BASESTAMP_SERVER` - Override default server URL
  - `BASESTAMP_VERBOSE` - Enable verbose output (set to "true")
  - `BASESTAMP_CONFIG` - Override config file path

## How It Works

1. **File Hashing**: Your file is hashed locally using SHA256
2. **Privacy Nonce** (CLI file mode): the CLI submits `SHA256(file_hash_hex + random_nonce_hex)` and
   stores the nonce in the `.basestamp` file
3. **Batch Processing**: Every ~5s the server builds a Merkle tree over the pending hashes
4. **Blockchain Anchoring**: The root is passed to `stamp(bytes32)` on the Basestamp contract
5. **Proof Generation**: `GET /stamp/{id}` returns the proof, batch nonce and transaction
6. **Trustless Verification**: Anyone can verify proofs independently

### Proof format (what `Verify` checks)

Given the submitted hash `hash` (64 lowercase hex chars) and the API response:

1. **Leaf**: `merkle_proof.leaf_hash == SHA256(utf8(nonce + hash))`, where `nonce` is the top-level
   `nonce` field (a decimal batch nonce). The two strings are concatenated as text; the hash is not
   hex-decoded. (Legacy proofs without a nonce: `leaf_hash == hash`.)
2. **Path**: starting from the leaf, for each sibling `parent = SHA256(min(a, b) || max(a, b))` over
   the raw 32-byte values (sorted pair; an odd last node is paired with itself). Because pairs are
   sorted, `directions` are informational and do not change the result. The final value must equal
   `merkle_proof.root_hash`, which must equal `merkle_root`.
3. **On-chain** (Base mainnet, chain 8453, contract `0x634494cB65B17163A4ca84378900Ff53A4Bba05C`,
   signer `0x0a3861972b28e6be9fEB826dd809aEB4F473e753`): via JSON-RPC, `eth_chainId` is 8453; the
   receipt of `tx_id` has status 1 and `to == contract`; it contains a
   `Stamped(bytes32 indexed hash, uint256 timestamp, uint256 blockNumber, address indexed submitter)`
   log from the contract with `hash == root` and `submitter == signer`; the transaction input is
   `stamp(root)` (`0xdd89581f`) sent by the signer; and the block has at least one confirmation.

The chain is pinned by the client, never taken from the server response.

## Security

- Files never leave your machine - only hashes are sent
- Privacy nonces prevent rainbow table attacks
- Merkle proofs provide cryptographic guarantees
- Blockchain provides immutable timestamping
- Open source for full transparency

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Links

- [BaseStamp Website](https://basestamp.io)
- [Python Client](https://github.com/basestamp/basestamp-python)
- [Documentation](https://docs.basestamp.io)
- [API Documentation](https://basestamp.io/docs/mcp)