# BaseStamp Go Client Library & CLI

BaseStamp is a cryptographic timestamping service that anchors file hashes to the blockchain, providing immutable proof of when your files existed. This repository contains the official Go client library and command-line interface.

## Features

- **Go Client Library**: Easy-to-use API similar to the Python client
- **Command-Line Interface**: Simple CLI tool for timestamping files
- **Blockchain Verification**: Trustless verification using Merkle proofs
- **Privacy Protection**: Uses nonces to protect file contents
- **Multiple Networks**: Supports Ethereum, Base, and other EVM chains

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
    
    // Verify the stamp
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
```

## API Reference

### Client Methods

- `NewClient()` - Create client with default API URL
- `NewClientWithURL(url)` - Create client with custom API URL
- `SubmitSHA256(hash)` - Submit hash for timestamping
- `GetStamp(stampID, opts)` - Get stamp with configurable options

### Stamp Methods

- `Verify(hash)` - Verify hash against Merkle proof
- `GetHash()` - Get the timestamped hash
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

// Verify file against its stamp file
valid, err := basestamp.VerifyFileStamp("document.pdf", "document.pdf.basestamp")

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
```

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

- **Server URL**: Default is `https://api.basestamp.io`
- **Config File**: `~/.basestamp.yaml` (optional)
- **Environment Variables**: 
  - `BASESTAMP_SERVER` - Override default server URL
  - `BASESTAMP_VERBOSE` - Enable verbose output (set to "true")
  - `BASESTAMP_CONFIG` - Override config file path

## How It Works

1. **File Hashing**: Your file is hashed locally using SHA256
2. **Privacy Nonce**: A random nonce is added for privacy (like OpenTimestamps)
3. **Batch Processing**: Hashes are batched into Merkle trees for efficiency
4. **Blockchain Anchoring**: Merkle roots are written to the blockchain
5. **Proof Generation**: Merkle proofs are generated for verification
6. **Trustless Verification**: Anyone can verify proofs independently

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
- [API Documentation](https://api.basestamp.io)