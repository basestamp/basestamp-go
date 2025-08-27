package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/basestamp/basestamp-go/blockchain"
	"github.com/basestamp/basestamp-go/crypto"
	"github.com/basestamp/basestamp-go/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// VerificationError represents a verification failure (not a user input error)
type VerificationError struct {
	Message string
}

func (e *VerificationError) Error() string {
	return e.Message
}

// NewVerificationError creates a new verification error
func NewVerificationError(message string) *VerificationError {
	return &VerificationError{Message: message}
}

var verifyCmd = &cobra.Command{
	Use:   "verify [file] [stamp-file]",
	Short: "Verify a timestamp proof for a file or hash",
	Long: `Verify that a file matches its timestamp proof by checking the hash
and validating the proof against the blockchain.

The verify command can work in three modes:
1. File mode: Computes the SHA256 hash of the specified file and compares with stamp file
2. Hash mode: Verifies a hash directly against a stamp file using --hash flag
3. JSON mode: Reads stamp JSON from stdin and verifies against hash via --hash flag

The command validates the blockchain proof to ensure authenticity.`,
	Args: cobra.MaximumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		err := runVerify(cmd, args)
		// For verification errors, suppress usage and just show the error
		if _, isVerificationError := err.(*VerificationError); isVerificationError {
			fmt.Fprintf(os.Stderr, "❌ %s\n", err.Error())
			os.Exit(1)
		}
		return err
	},
	Example: `  # Verify a file against its automatic stamp file
  basestamp verify document.pdf

  # Verify a file against a specific stamp file
  basestamp verify document.pdf document.stamp

  # Verify a hash against a stamp file
  basestamp verify --hash e3b0c44... document.stamp

  # Verify a hash against stamp JSON from stdin
  cat stamp.json | basestamp verify --hash e3b0c44...

  # Verify with verbose output
  basestamp verify document.pdf --verbose

  # Verify using a different server
  basestamp verify document.pdf --server https://api.basestamp.io`,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	
	verifyCmd.Flags().StringP("hash", "H", "", "hash to verify directly instead of calculating from file")
}

func runVerify(cmd *cobra.Command, args []string) error {
	hashFlag, _ := cmd.Flags().GetString("hash")
	
	// Determine mode: hash mode, file mode, or JSON stdin mode
	var hash string
	var filename string
	var stampFile string
	var hashMode bool
	var stdinMode bool
	
	if hashFlag != "" {
		// Hash provided via flag
		hash = strings.TrimSpace(hashFlag)
		hashMode = true
		
		// Validate hash format
		if len(hash) != 64 {
			return fmt.Errorf("invalid hash length: expected 64 characters, got %d", len(hash))
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return fmt.Errorf("invalid hash format: must be hexadecimal")
		}
		
		if len(args) == 0 {
			// No args - read stamp JSON from stdin
			stdinMode = true
		} else if len(args) == 1 {
			// One arg - stamp file provided
			stampFile = args[0]
		} else {
			return fmt.Errorf("when using --hash flag, provide either stamp file or use stdin")
		}
	} else {
		// File mode
		if len(args) == 0 {
			return fmt.Errorf("file argument required when not using --hash flag")
		}
		
		filename = args[0]
		hashMode = false
		
		// If stamp file not provided, use automatic .basestamp file
		if len(args) == 2 {
			stampFile = args[1]
		} else {
			stampFile = filename + ".basestamp"
		}
	}

	var stampData []byte
	var err error
	
	if stdinMode {
		// Read stamp JSON from stdin
		if verbose {
			fmt.Printf("Reading stamp JSON from stdin...\n")
		}
		stampData, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read stamp JSON from stdin: %w", err)
		}
	} else {
		// Read stamp from file
		if verbose {
			if hashMode {
				fmt.Printf("Verifying hash: %s\n", hash)
			} else {
				fmt.Printf("Verifying file: %s\n", filename)
			}
			fmt.Printf("Using stamp file: %s\n", stampFile)
		}
		
		stampData, err = os.ReadFile(stampFile)
		if err != nil {
			return fmt.Errorf("failed to read stamp file: %w", err)
		}
	}
	
	if stdinMode {
		// For stdin mode, try to parse as server response format first
		var serverResponse map[string]interface{}
		if err := json.Unmarshal(stampData, &serverResponse); err == nil {
			// This looks like server response JSON - verify directly
			return verifyServerResponse(hash, serverResponse)
		}
	}
	
	// Try to parse as FileStamp format
	var stamp types.FileStamp
	if err := json.Unmarshal(stampData, &stamp); err != nil {
		return fmt.Errorf("failed to parse stamp data: %w", err)
	}

	// Check if we have a stamp ID (new format)
	if stamp.StampID != "" {
		if hashMode {
			return verifyWithStampIDAndHash(hash, &stamp)
		} else {
			return verifyWithStampID(filename, &stamp)
		}
	}

	// Fall back to legacy verification
	if hashMode {
		return fmt.Errorf("legacy stamp format not supported with --hash flag")
	}
	return verifyLegacy(filename, &stamp, stampFile)
}

func verifyWithStampID(filename string, stamp *types.FileStamp) error {
	serverURL := viper.GetString("server")
	
	if verbose {
		fmt.Printf("🔍 DEBUG: Starting verification with stamp ID: %s\n", stamp.StampID)
		fmt.Printf("🔍 DEBUG: Server URL: %s\n", serverURL)
	}
	
	// Step 1: Verify the file hash matches what we stamped
	if stamp.Nonce != "" && stamp.FileHash != "" {
		// New format with nonce
		stampedHash := &crypto.StampedHash{
			FileHash: stamp.FileHash,
			Nonce:    stamp.Nonce,
			Hash:     stamp.Hash,
		}
		
		if err := crypto.VerifyStampedHash(filename, stampedHash); err != nil {
			return NewVerificationError(fmt.Sprintf("File verification failed: %v", err))
		}
		
		fmt.Printf("✅ File hash verification successful\n")
		fmt.Printf("   📄 File: %s\n", filename)
		fmt.Printf("   📊 SHA256: %s\n", stamp.FileHash)
		fmt.Printf("   🎲 Nonce: %s\n", stamp.Nonce)
		fmt.Printf("   🔒 Stamped hash: %s\n", stamp.Hash)
	} else {
		// Legacy format without nonce
		hash, err := crypto.HashFile(filename)
		if err != nil {
			return fmt.Errorf("failed to hash file: %w", err)
		}

		if hash != stamp.Hash {
			return NewVerificationError("File hash mismatch")
		}
		
		fmt.Printf("✅ File hash verification successful\n")
		fmt.Printf("   📄 File: %s\n", filename)
		fmt.Printf("   📊 SHA256: %s\n", hash)
	}

	// Step 2: Get stamp data from server for client-side verification
	stampURL := serverURL + "/stamp/" + stamp.StampID
	
	if verbose {
		fmt.Printf("🔍 DEBUG: GET %s\n", stampURL)
	}

	resp, err := http.Get(stampURL)
	if err != nil {
		return fmt.Errorf("failed to send verify request: %w", err)
	}
	defer resp.Body.Close()

	if verbose {
		fmt.Printf("🔍 DEBUG: Response status: %s\n", resp.Status)
	}

	if resp.StatusCode != http.StatusOK {
		// Read error response for debugging
		if verbose {
			bodyBytes, _ := io.ReadAll(resp.Body)
			fmt.Printf("🔍 DEBUG: Error response body: %s\n", string(bodyBytes))
		}
		return fmt.Errorf("server returned error: %s", resp.Status)
	}

	// Read and debug the response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if verbose {
		fmt.Printf("🔍 DEBUG: Response body: %s\n", string(bodyBytes))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return fmt.Errorf("failed to decode verify response: %w", err)
	}

	if verbose {
		fmt.Printf("🔍 DEBUG: Parsed response:\n")
		for key, value := range result {
			fmt.Printf("  %s: %v\n", key, value)
		}
	}

	// Step 2: Use unified verification function
	return performCompleteVerification(stamp.Hash, result)
}

func verifyWithStampIDAndHash(hash string, stamp *types.FileStamp) error {
	serverURL := viper.GetString("server")
	
	if verbose {
		fmt.Printf("🔍 DEBUG: Starting verification with stamp ID: %s\n", stamp.StampID)
		fmt.Printf("🔍 DEBUG: Server URL: %s\n", serverURL)
		fmt.Printf("🔍 DEBUG: Hash to verify: %s\n", hash)
	}
	
	// Step 1: Verify the hash matches what we stamped
	if stamp.Nonce != "" && stamp.FileHash != "" {
		// New format with nonce - check if hash matches either file hash or stamped hash
		if hash != stamp.FileHash && hash != stamp.Hash {
			return NewVerificationError(fmt.Sprintf("Hash mismatch: provided hash %s does not match file hash %s or stamped hash %s", hash, stamp.FileHash, stamp.Hash))
		}
		
		fmt.Printf("✅ Hash verification successful\n")
		if hash == stamp.FileHash {
			fmt.Printf("   📊 Verified against original file hash: %s\n", stamp.FileHash)
			fmt.Printf("   🎲 Nonce: %s\n", stamp.Nonce)
			fmt.Printf("   🔒 Stamped hash: %s\n", stamp.Hash)
		} else {
			fmt.Printf("   🔒 Verified against stamped hash: %s\n", stamp.Hash)
		}
	} else {
		// Legacy format without nonce
		if hash != stamp.Hash {
			return NewVerificationError(fmt.Sprintf("Hash mismatch: provided hash %s does not match stamp hash %s", hash, stamp.Hash))
		}
		
		fmt.Printf("✅ Hash verification successful\n")
		fmt.Printf("   📊 SHA256: %s\n", hash)
	}

	// Step 2: Get stamp data from server for client-side verification
	stampURL := serverURL + "/stamp/" + stamp.StampID
	
	if verbose {
		fmt.Printf("🔍 DEBUG: GET %s\n", stampURL)
	}

	resp, err := http.Get(stampURL)
	if err != nil {
		return fmt.Errorf("failed to send verify request: %w", err)
	}
	defer resp.Body.Close()

	if verbose {
		fmt.Printf("🔍 DEBUG: Response status: %s\n", resp.Status)
	}

	if resp.StatusCode != http.StatusOK {
		if verbose {
			bodyBytes, _ := io.ReadAll(resp.Body)
			fmt.Printf("🔍 DEBUG: Error response body: %s\n", string(bodyBytes))
		}
		return fmt.Errorf("server returned error: %s", resp.Status)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if verbose {
		fmt.Printf("🔍 DEBUG: Response body: %s\n", string(bodyBytes))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		return fmt.Errorf("failed to decode verify response: %w", err)
	}

	return performCompleteVerification(hash, result)
}

func verifyServerResponse(hash string, response map[string]interface{}) error {
	if verbose {
		fmt.Printf("🔍 DEBUG: Verifying hash against server response JSON\n")
		fmt.Printf("🔍 DEBUG: Hash to verify: %s\n", hash)
	}
	
	// Check if the hash in the response matches our input
	responseHash, ok := response["hash"].(string)
	if !ok {
		return fmt.Errorf("no hash found in stamp JSON")
	}
	
	if responseHash != hash {
		return NewVerificationError(fmt.Sprintf("Hash mismatch: provided hash %s does not match stamp hash %s", hash, responseHash))
	}
	
	fmt.Printf("✅ Hash verification successful\n")
	fmt.Printf("   📊 SHA256: %s\n", hash)
	
	return performCompleteVerification(hash, response)
}

// performCompleteVerification performs unified verification for both hash and file modes
func performCompleteVerification(hash string, result map[string]interface{}) error {
	// Extract data from response
	merkleRoot, _ := result["merkle_root"].(string)
	txID, _ := result["tx_id"].(string)
	network, _ := result["network"].(string)
	status, _ := result["status"].(string)
	stampID, _ := result["stamp_id"].(string)
	
	fmt.Printf("   🆔 Stamp ID: %s\n", stampID)
	fmt.Printf("   📊 Status: %s\n", status)

	// Check if we have a merkle proof for verification
	merkleProofData, hasMerkleProof := result["merkle_proof"].(map[string]interface{})
	if !hasMerkleProof {
		// No merkle proof yet - show status
		if status == "batched" {
			fmt.Printf("   ⏳ Awaiting blockchain confirmation\n")
			fmt.Printf("   💡 The merkle root has been submitted to blockchain but not yet confirmed\n")
			fmt.Printf("   🔄 Check again in a few minutes for merkle proof\n")
		} else if status == "pending" {
			fmt.Printf("   ⏳ Queued for batching\n")
			fmt.Printf("   💡 Your stamp will be included in the next batch (every 5 seconds)\n")
		} else {
			fmt.Printf("   ❓ Merkle proof not available for status: %s\n", status)
		}
		return fmt.Errorf("merkle proof not yet available")
	}

	// Step 1: Perform complete blockchain verification (unified path)
	fmt.Printf("\n🔍 Performing complete blockchain verification...\n")
	
	// Convert the merkle proof data to our types format
	merkleProof := &types.MerkleProof{}
	if leafHash, ok := merkleProofData["leaf_hash"].(string); ok {
		merkleProof.LeafHash = leafHash
	}
	if leafIndex, ok := merkleProofData["leaf_index"].(float64); ok {
		merkleProof.LeafIndex = int(leafIndex)
	}
	if rootHash, ok := merkleProofData["root_hash"].(string); ok {
		merkleProof.RootHash = rootHash
	}
	if siblingsInterface, ok := merkleProofData["siblings"].([]interface{}); ok {
		siblings := make([]string, len(siblingsInterface))
		for i, s := range siblingsInterface {
			if siblingStr, ok := s.(string); ok {
				siblings[i] = siblingStr
			}
		}
		merkleProof.Siblings = siblings
	}
	if directionsInterface, ok := merkleProofData["directions"].([]interface{}); ok {
		directions := make([]bool, len(directionsInterface))
		for i, d := range directionsInterface {
			if directionBool, ok := d.(bool); ok {
				directions[i] = directionBool
			}
		}
		merkleProof.Directions = directions
	}
	if nonce, ok := merkleProofData["nonce"].(string); ok {
		merkleProof.Nonce = nonce
	}

	if verbose {
		fmt.Printf("🔍 DEBUG: Merkle proof details:\n")
		fmt.Printf("  Leaf hash: %s\n", merkleProof.LeafHash)
		fmt.Printf("  Leaf index: %d\n", merkleProof.LeafIndex) 
		fmt.Printf("  Root hash: %s\n", merkleProof.RootHash)
		fmt.Printf("  Siblings count: %d\n", len(merkleProof.Siblings))
		fmt.Printf("  Nonce: %s\n", merkleProof.Nonce)
	}

	// Create a complete proof structure for blockchain verification
	blockNumber, _ := result["block_number"].(float64)
	proof := &types.Proof{
		Network:     network,
		TxID:        txID,
		BlockHash:   getStringFromMap(result, "block_hash"),
		BlockNumber: uint64(blockNumber),
		Status:      status,
		MerkleRoot:  merkleRoot,
		MerkleProof: merkleProof,
	}

	// Perform complete blockchain verification with detailed logging
	fmt.Printf("   🔗 Querying blockchain transaction: %s\n", txID)
	verifier := blockchain.NewVerifier()
	if err := verifier.VerifyProof(proof); err != nil {
		fmt.Printf("❌ Blockchain verification failed: %v\n", err)
		fmt.Printf("   🔍 This could indicate:\n")
		fmt.Printf("   • Transaction not found on blockchain\n")
		fmt.Printf("   • Merkle root mismatch with on-chain data\n")
		fmt.Printf("   • Insufficient confirmations\n")
		fmt.Printf("   • Invalid merkle proof structure\n")
		fmt.Printf("\n❌ VERIFICATION FAILED\n")
		return NewVerificationError(fmt.Sprintf("Blockchain verification failed: %v", err))
	}

	fmt.Printf("✅ BLOCKCHAIN VERIFICATION SUCCESSFUL\n")
	fmt.Printf("   🔒 Merkle proof is mathematically valid\n")
	fmt.Printf("   ⛓️  Transaction verified on blockchain\n")
	fmt.Printf("   🌳 Merkle root matches on-chain data\n")
	fmt.Printf("   ✓ Blockchain calldata verified\n")
	fmt.Printf("   🧾 Transaction: %s\n", txID)
	
	explorerURL := getBlockchainExplorerURL(network, txID)
	if explorerURL != "" {
		fmt.Printf("   🔗 Explorer: %s\n", explorerURL)  
	}
	
	fmt.Printf("\n🎉 VERIFICATION SUCCESSFUL: Hash is authentic and timestamped on blockchain\n")
	return nil
}

func verifyLegacy(filename string, stamp *types.FileStamp, stampFile string) error {
	fmt.Printf("⚠️  Legacy verification not yet implemented in new system\n")
	fmt.Printf("   This stamp file was created with an older version\n")
	fmt.Printf("   Please re-stamp the file to use the new verification system\n")
	return fmt.Errorf("legacy verification not supported")
}




// getBlockchainExplorerURL returns the blockchain explorer URL for a given network and transaction ID
func getBlockchainExplorerURL(network, txID string) string {
	switch network {
	case "BASE Sepolia":
		return fmt.Sprintf("https://sepolia.basescan.org/tx/%s", txID)
	case "BASE":
		return fmt.Sprintf("https://basescan.org/tx/%s", txID)
	case "Ethereum":
		return fmt.Sprintf("https://etherscan.io/tx/%s", txID)
	case "Ethereum Sepolia":
		return fmt.Sprintf("https://sepolia.etherscan.io/tx/%s", txID)
	case "Polygon":
		return fmt.Sprintf("https://polygonscan.com/tx/%s", txID)
	case "Arbitrum":
		return fmt.Sprintf("https://arbiscan.io/tx/%s", txID)
	case "Optimism":
		return fmt.Sprintf("https://optimistic.etherscan.io/tx/%s", txID)
	default:
		return ""
	}
}

