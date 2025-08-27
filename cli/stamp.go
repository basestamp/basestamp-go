package cli

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/basestamp/basestamp-go"
	"github.com/basestamp/basestamp-go/crypto"
	"github.com/basestamp/basestamp-go/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var stampCmd = &cobra.Command{
	Use:   "stamp [file]",
	Short: "Create a timestamp proof for a file or hash",
	Long: `Create a cryptographic timestamp proof for a file by calculating its hash
and submitting it to the BaseStamp server for blockchain anchoring.

The stamp command can work in two modes:
1. File mode: Computes the SHA256 hash of the specified file and submits it
2. Hash mode: Accepts a hash directly via --hash flag or stdin

In file mode, the command creates a complete proof file. In hash mode,
it prints the timestamp proof directly to stdout.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runStamp,
	Example: `  # Stamp a file (creates document.pdf.basestamp automatically)
  basestamp stamp document.pdf

  # Stamp with custom output file
  basestamp stamp document.pdf --output document.stamp

  # Stamp a hash directly
  basestamp stamp --hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

  # Stamp a hash from stdin
  echo "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" | basestamp stamp

  # Stamp with verbose output
  basestamp stamp document.pdf --verbose

  # Stamp using a different server
  basestamp stamp document.pdf --server https://api.basestamp.io`,
}

func init() {
	rootCmd.AddCommand(stampCmd)
	
	stampCmd.Flags().StringP("output", "o", "", "output file for the timestamp proof (file mode only)")
	stampCmd.Flags().StringP("hash", "H", "", "hash to timestamp directly instead of calculating from file")
	// Note: --wait flag kept for backward compatibility but is now always enabled
	stampCmd.Flags().BoolP("wait", "w", false, "(deprecated) always waits for confirmation")
}

func runStamp(cmd *cobra.Command, args []string) error {
	hashFlag, _ := cmd.Flags().GetString("hash")
	outputFile, _ := cmd.Flags().GetString("output")
	
	// Determine mode: hash mode or file mode
	var hash string
	var filename string
	var hashMode bool
	
	if hashFlag != "" {
		// Hash provided via flag
		hash = strings.TrimSpace(hashFlag)
		hashMode = true
	} else if len(args) == 0 {
		// No arguments - read hash from stdin
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			return fmt.Errorf("no hash provided via stdin")
		}
		hash = strings.TrimSpace(scanner.Text())
		if hash == "" {
			return fmt.Errorf("empty hash provided via stdin")
		}
		hashMode = true
	} else {
		// File mode
		filename = args[0]
		hashMode = false
	}
	
	// Validate hash format in hash mode
	if hashMode {
		if len(hash) != 64 {
			return fmt.Errorf("invalid hash length: expected 64 characters, got %d", len(hash))
		}
		if _, err := hex.DecodeString(hash); err != nil {
			return fmt.Errorf("invalid hash format: must be hexadecimal")
		}
		if outputFile != "" {
			return fmt.Errorf("--output flag cannot be used in hash mode (output goes to stdout)")
		}
	}

	var stampedHash *crypto.StampedHash
	
	if hashMode {
		// Hash mode - use provided hash directly
		if verbose {
			fmt.Fprintf(os.Stderr, "Stamping hash: %s\n", hash)
		}
		stampedHash = &crypto.StampedHash{
			Hash:     hash,
			FileHash: hash, // In hash mode, these are the same
			Nonce:    "",   // No nonce when hash is provided directly
		}
	} else {
		// File mode - calculate hash from file
		if outputFile == "" {
			outputFile = filename + ".basestamp"
		}
		
		if verbose {
			fmt.Printf("Stamping file: %s\n", filename)
		}
		
		// Create timestamped hash with nonce for privacy (like OpenTimestamps)
		var err error
		stampedHash, err = crypto.CreateStampedHash(filename)
		if err != nil {
			return fmt.Errorf("failed to create timestamped hash: %w", err)
		}
		
		if verbose {
			fmt.Printf("File hash: %s\n", stampedHash.FileHash)
			fmt.Printf("Nonce: %s\n", stampedHash.Nonce)
			fmt.Printf("Timestamped hash: %s\n", stampedHash.Hash)
		}
	}

	serverURL := viper.GetString("server")
	request := types.CalendarRequest{
		Hash: stampedHash.Hash, // Send the timestamped hash (with nonce)
	}

	reqBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	if verbose {
		fmt.Printf("🔍 DEBUG: POST %s/stamp\n", serverURL)
		fmt.Printf("🔍 DEBUG: Request body: %s\n", string(reqBody))
	}

	resp, err := http.Post(serverURL+"/stamp", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if verbose {
		fmt.Printf("🔍 DEBUG: Response status: %s\n", resp.Status)
	}

	// Read response body for debugging
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if verbose {
		fmt.Printf("🔍 DEBUG: Response body: %s\n", string(bodyBytes))
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned error: %s", resp.Status)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract stamp ID from response
	stampID, ok := response["stamp_id"].(string)
	if !ok {
		return fmt.Errorf("server did not return stamp_id")
	}

	if hashMode {
		fmt.Fprintf(os.Stderr, "Hash: %s\n", stampedHash.Hash)
		fmt.Fprintf(os.Stderr, "Stamp ID: %s\n", stampID)
	} else {
		fmt.Printf("File: %s\n", filename)
		fmt.Printf("Hash: %s\n", stampedHash.Hash)
		fmt.Printf("Stamp ID: %s\n", stampID)
	}

	// Always wait for completion
	if hashMode {
		fmt.Fprintln(os.Stderr, "Waiting for blockchain confirmation...")
	} else {
		fmt.Println("Waiting for blockchain confirmation...")
	}
	finalStatus, err := waitForConfirmation(stampID, hashMode)
	if err != nil {
		return fmt.Errorf("failed to wait for confirmation: %w", err)
	}

	if hashMode {
		// Hash mode - print complete stamp JSON to stdout
		stampJSON, err := json.MarshalIndent(finalStatus, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal stamp JSON: %w", err)
		}
		fmt.Print(string(stampJSON))
	} else {
		// File mode - create proof file with complete blockchain data
		fileStamp := types.FileStamp{
			Filename:  filename,
			Hash:      stampedHash.Hash,     // The hash sent to server (with nonce)
			FileHash:  stampedHash.FileHash, // Original file hash
			Nonce:     stampedHash.Nonce,    // Privacy nonce
			Algorithm: "SHA256",
			CreatedAt: time.Now(),
			Proofs:    []types.Proof{},     // Will be populated with complete data
			StampID:   stampID,
		}

		// Fetch and populate complete blockchain data from API
		client := basestamp.NewClientWithURL(viper.GetString("server"))
		if err := basestamp.UpdateFileStampWithBlockchainData(&fileStamp, client); err != nil {
			if verbose {
				fmt.Printf("⚠️  Warning: Could not fetch complete blockchain data: %v\n", err)
			}
			// Continue with basic data for now
			proof := types.Proof{
				Network:   getStringFromMap(finalStatus, "network"),
				Status:    getStringFromMap(finalStatus, "status"),
				TxID:      getStringFromMap(finalStatus, "tx_id"),
				StampedAt: time.Now(),
			}
			fileStamp.Proofs = []types.Proof{proof}
		}

		// Save the complete stamp file
		if err := saveStampToFile(fileStamp, outputFile); err != nil {
			return fmt.Errorf("failed to save stamp: %w", err)
		}
		
		fmt.Printf("Timestamp proof saved to: %s\n", outputFile)
		fmt.Println("Timestamp confirmed on blockchain!")
	}

	return nil
}


func waitForConfirmation(stampID string, hashMode bool) (map[string]interface{}, error) {
	serverURL := viper.GetString("server")
	
	if verbose {
		fmt.Printf("🔍 DEBUG: Waiting for confirmation of stamp ID: %s\n", stampID)
	}
	
	for i := 0; i < 60; i++ {
		if verbose {
			fmt.Printf("🔍 DEBUG: Checking status (attempt %d/60)...\n", i+1)
		}
		
		time.Sleep(10 * time.Second)
		
		// Use the correct endpoint - /stamp/{stampId} for status
		statusURL := serverURL + "/stamp/" + stampID
		
		if verbose {
			fmt.Printf("🔍 DEBUG: GET %s\n", statusURL)
		}
		
		resp, err := http.Get(statusURL)
		if err != nil {
			if verbose {
				fmt.Printf("🔍 DEBUG: Request failed: %v\n", err)
			}
			continue
		}
		
		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		if err != nil {
			if verbose {
				fmt.Printf("🔍 DEBUG: Failed to read response: %v\n", err)
			}
			continue
		}
		
		if verbose {
			fmt.Printf("🔍 DEBUG: Response status: %s\n", resp.Status)
			fmt.Printf("🔍 DEBUG: Response body: %s\n", string(bodyBytes))
		}
		
		if resp.StatusCode != http.StatusOK {
			if verbose {
				fmt.Printf("🔍 DEBUG: Server returned error: %s\n", resp.Status)
			}
			continue
		}
		
		var status map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &status); err != nil {
			if verbose {
				fmt.Printf("🔍 DEBUG: Failed to decode response: %v\n", err)
			}
			continue
		}
		
		if statusStr, ok := status["status"].(string); ok {
			if statusStr == "confirmed" {
				if hashMode {
					fmt.Fprintf(os.Stderr, "✅ Confirmed! TX: %s\n", status["tx_id"])
					if explorerURL := getExplorerURL(status["network"], status["tx_id"]); explorerURL != "" {
						fmt.Fprintf(os.Stderr, "🔗 Explorer: %s\n", explorerURL)
					}
				} else {
					fmt.Printf("✅ Confirmed! TX: %s\n", status["tx_id"])
					if explorerURL := getExplorerURL(status["network"], status["tx_id"]); explorerURL != "" {
						fmt.Printf("🔗 Explorer: %s\n", explorerURL)
					}
				}
				
				// Note: Advanced blockchain verification would require additional infrastructure
				
				return status, nil
			} else if statusStr == "failed" {
				return nil, fmt.Errorf("timestamp failed: %s", status["message"])
			}
			
			if hashMode {
				fmt.Fprintf(os.Stderr, "⏳ Status: %s", statusStr)
				if message, ok := status["message"].(string); ok {
					fmt.Fprintf(os.Stderr, " - %s", message)
				}
				fmt.Fprintln(os.Stderr)
			} else {
				fmt.Printf("⏳ Status: %s", statusStr)
				if message, ok := status["message"].(string); ok {
					fmt.Printf(" - %s", message)
				}
				fmt.Println()
			}
		}
	}
	
	return nil, fmt.Errorf("timeout waiting for confirmation after 10 minutes")
}

// getExplorerURL returns the explorer URL for a transaction
func getExplorerURL(networkInterface, txIDInterface interface{}) string {
	network, ok1 := networkInterface.(string)
	txID, ok2 := txIDInterface.(string)
	
	if !ok1 || !ok2 || txID == "" {
		return ""
	}
	
	switch network {
	case "BASE Sepolia":
		return fmt.Sprintf("https://sepolia.basescan.org/tx/%s", txID)
	case "BASE":
		return fmt.Sprintf("https://basescan.org/tx/%s", txID)
	default:
		return ""
	}
}

// getStringFromMap safely extracts a string value from a map
func getStringFromMap(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

