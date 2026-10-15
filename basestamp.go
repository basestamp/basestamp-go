// Package basestamp provides a Go client library for BaseStamp timestamping service.
//
// # Usage
//
//	client := basestamp.NewClient()
//
//	// Calculate hash of your data
//	hash := basestamp.CalculateSHA256("Hello, BaseStamp!")
//
//	// Submit hash for timestamping
//	stampID, err := client.SubmitSHA256(hash)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Get the stamp with proof
//	stamp, err := client.GetStamp(stampID, nil) // Use defaults (Wait: true)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Verify the timestamp: leaf binding, merkle path and on-chain anchor
//	valid, err := stamp.Verify(hash)
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Timestamp is valid: %v\n", valid)
//
// # Proof format
//
// The server places leaf_hash = SHA256(utf8(nonce + hash)) in a binary merkle
// tree, where nonce is the batch nonce (top-level "nonce" field of
// GET /stamp/{id}) and hash is the submitted lowercase hex hash. Parents are
// SHA256(min(a,b) || max(a,b)) over the raw 32-byte children (sorted pair, so
// "directions" do not change the result); an odd node is paired with itself.
// The root is passed to stamp(bytes32) on the Basestamp contract, which emits
// Stamped(root, timestamp, blockNumber, submitter).
package basestamp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/basestamp/basestamp-go/blockchain"
	"github.com/basestamp/basestamp-go/crypto"
	"github.com/basestamp/basestamp-go/merkle"
	"github.com/basestamp/basestamp-go/types"
)

// Network endpoints and on-chain parameters.
const (
	// MainnetAPIURL is the Base mainnet (chain 8453) BaseStamp API. This is the default.
	MainnetAPIURL = "https://api-mainnet.basestamp.io"
	// SepoliaAPIURL is the Base Sepolia testnet (chain 84532) BaseStamp API.
	SepoliaAPIURL = "https://api-sepolia.basestamp.io"

	MainnetChainID         = 8453
	MainnetContractAddress = "0x634494cB65B17163A4ca84378900Ff53A4Bba05C"
	MainnetSignerAddress   = "0x0a3861972b28e6be9fEB826dd809aEB4F473e753"
	MainnetRPCURL          = "https://mainnet.base.org"

	SepoliaChainID         = 84532
	SepoliaContractAddress = "0x15Adb2cc1aEDB6610E1C801BE7E205be3A8De5d7"
	SepoliaRPCURL          = "https://sepolia.base.org"

	// DefaultAPIURL is used when no URL is given. Defaults to Base mainnet since v0.2.0.
	DefaultAPIURL = MainnetAPIURL

	// maxAPIResponseBytes caps how much of an API response is read.
	maxAPIResponseBytes = 1 << 20
)

// Client represents a BaseStamp API client
type Client struct {
	apiURL     string
	httpClient *http.Client
	chain      blockchain.ChainConfig
	rpcClient  *http.Client
}

// GetStampOptions configures the behavior of GetStamp requests
type GetStampOptions struct {
	// Wait determines if the client should poll until the stamp is confirmed
	// with a merkle proof. nil = default (true), false = no waiting, true = wait
	Wait *bool

	// MaxAttempts specifies maximum number of polling attempts (default: 30)
	MaxAttempts int

	// RetryDelay specifies delay between polling attempts (default: 2s)
	RetryDelay time.Duration

	// Context for cancellation (default: context.Background())
	Context context.Context
}

// Helper functions for creating GetStampOptions with common configurations

// BoolPtr returns a pointer to a bool value (helper for GetStampOptions.Wait)
func BoolPtr(b bool) *bool {
	return &b
}

// NoWait returns GetStampOptions configured to not wait for merkle proof
func NoWait() *GetStampOptions {
	return &GetStampOptions{Wait: BoolPtr(false)}
}

// NewClient creates a new BaseStamp client with default settings (Base mainnet).
func NewClient() *Client {
	return NewClientWithURL(DefaultAPIURL)
}

// NewClientWithURL creates a new BaseStamp client with a custom API URL.
//
// On-chain verification is pinned to Base mainnet unless apiURL is
// SepoliaAPIURL; use WithChain to select another deployment. The chain is never
// taken from the server's response, so a server cannot redirect verification
// to a network where anyone can stamp.
func NewClientWithURL(apiURL string) *Client {
	apiURL = strings.TrimSuffix(strings.TrimSpace(apiURL), "/")
	chain := blockchain.Mainnet
	if apiURL == SepoliaAPIURL {
		chain = blockchain.Sepolia
	}
	return &Client{
		apiURL: apiURL,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: NewUserAgentTransport(UserAgent(), nil),
		},
		chain: chain,
	}
}

// WithChain sets the Basestamp deployment used for on-chain verification.
func (c *Client) WithChain(cfg blockchain.ChainConfig) *Client {
	c.chain = cfg
	return c
}

// WithRPCHTTPClient sets the HTTP client used for blockchain JSON-RPC calls.
func (c *Client) WithRPCHTTPClient(h *http.Client) *Client {
	c.rpcClient = h
	return c
}

// Chain returns the deployment used for on-chain verification.
func (c *Client) Chain() blockchain.ChainConfig {
	return c.chain
}

// CalculateSHA256 calculates the SHA256 hash of the given data
func CalculateSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// CalculateSHA256Bytes calculates the SHA256 hash of the given bytes
func CalculateSHA256Bytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// NormalizeHash validates a 64-character hex hash (optional 0x prefix, any
// case) and returns it lowercased.
func NormalizeHash(hash string) (string, error) {
	return merkle.NormalizeHash(hash)
}

// SubmitSHA256 submits a SHA256 hash for timestamping and returns the stamp ID.
// The hash must be 64 hex characters; it is lowercased before submission so the
// server's leaf is computed over the canonical form.
func (c *Client) SubmitSHA256(hash string) (string, error) {
	return c.SubmitSHA256Context(context.Background(), hash)
}

// SubmitSHA256Context is SubmitSHA256 with a context.
func (c *Client) SubmitSHA256Context(ctx context.Context, hash string) (string, error) {
	h, err := merkle.NormalizeHash(hash)
	if err != nil {
		return "", err
	}
	reqBody, err := json.Marshal(types.CalendarRequest{Hash: h})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+"/stamp", strings.NewReader(string(reqBody)))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to submit hash: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseBytes))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server error %d: %s", resp.StatusCode, string(body))
	}

	var response struct {
		StampID string `json:"stamp_id"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}
	if response.StampID == "" {
		return "", fmt.Errorf("server response has no stamp_id")
	}
	return response.StampID, nil
}

// GetStamp retrieves a stamp by ID with configurable options.
// If opts is nil, defaults are used (Wait: true, MaxAttempts: 30, RetryDelay: 2s).
// When waiting, it polls until the stamp has a merkle proof and is confirmed,
// and returns an error if the server reports the stamp as failed.
func (c *Client) GetStamp(stampID string, opts *GetStampOptions) (*Stamp, error) {
	options := c.applyGetStampDefaults(opts)

	wait := true // default
	if options.Wait != nil {
		wait = *options.Wait
	}

	if !wait {
		return c.getStampOnce(stampID, options.Context)
	}

	for attempt := 0; attempt < options.MaxAttempts; attempt++ {
		select {
		case <-options.Context.Done():
			return nil, options.Context.Err()
		default:
		}

		stamp, err := c.getStampOnce(stampID, options.Context)
		if err != nil {
			return nil, err
		}
		if stamp.isReady() {
			return stamp, nil
		}
		if status, _ := stamp.response["status"].(string); status == "failed" {
			msg, _ := stamp.response["message"].(string)
			return nil, fmt.Errorf("stamp %s failed: %s", stampID, msg)
		}

		if attempt < options.MaxAttempts-1 {
			select {
			case <-options.Context.Done():
				return nil, options.Context.Err()
			case <-time.After(options.RetryDelay):
			}
		}
	}

	return nil, fmt.Errorf("timeout waiting for stamp to be ready after %d attempts", options.MaxAttempts)
}

// applyGetStampDefaults applies default values to GetStampOptions
func (c *Client) applyGetStampDefaults(opts *GetStampOptions) *GetStampOptions {
	if opts == nil {
		wait := true
		return &GetStampOptions{
			Wait:        &wait,
			MaxAttempts: 30,
			RetryDelay:  2 * time.Second,
			Context:     context.Background(),
		}
	}

	// Copy the struct to avoid modifying the original
	options := *opts

	if options.MaxAttempts <= 0 {
		options.MaxAttempts = 30
	}

	if options.RetryDelay <= 0 {
		options.RetryDelay = 2 * time.Second
	}

	if options.Context == nil {
		options.Context = context.Background()
	}

	return &options
}

func (c *Client) getStampOnce(stampID string, ctx context.Context) (*Stamp, error) {
	if strings.TrimSpace(stampID) == "" {
		return nil, fmt.Errorf("stamp ID is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL+"/stamp/"+url.PathEscape(stampID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get stamp: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(body))
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &Stamp{
		client:   c,
		StampID:  stampID,
		response: response,
	}, nil
}

// Stamp represents a timestamped hash with proof
type Stamp struct {
	client   *Client
	StampID  string
	response map[string]interface{}
}

// NewStampFromResponse wraps a GET /stamp/{id} JSON response (for example one
// saved to disk) so it can be verified. client may be nil, in which case Base
// mainnet is used for on-chain verification and the response is not refreshed.
func NewStampFromResponse(client *Client, response map[string]interface{}) *Stamp {
	id, _ := response["stamp_id"].(string)
	return &Stamp{client: client, StampID: id, response: response}
}

func (s *Stamp) isReady() bool {
	if _, ok := s.response["merkle_proof"].(map[string]interface{}); !ok {
		return false
	}
	status, _ := s.response["status"].(string)
	txID, _ := s.response["tx_id"].(string)
	return status == "confirmed" || txID != ""
}

// Verify checks that hash was timestamped by this stamp:
//
//  1. hash matches the stamp's hash and leaf_hash == SHA256(nonce + hash);
//  2. the merkle path reconstructs root_hash, which equals merkle_root;
//  3. the root was stamped on-chain by the Basestamp contract in tx_id
//     (receipt status, contract address, Stamped event, calldata, signer).
//
// It returns (false, nil) if hash is not the hash of this stamp, and
// (false, err) if the proof is invalid, not anchored, or cannot be checked
// (errors.Is(err, ErrInvalidProof) / errors.Is(err, blockchain.ErrNotAnchored)).
// Use VerifyDetailed for anchor details or VerifyOffline to skip the chain.
func (s *Stamp) Verify(hash string) (bool, error) {
	res, err := s.VerifyDetailed(context.Background(), hash)
	if err != nil {
		if errors.Is(err, ErrHashMismatch) {
			return false, nil
		}
		return false, err
	}
	return res.Valid, nil
}

// VerifyDetailed performs the same checks as Verify and returns the details.
// If the stamp has a client, the latest stamp data is fetched first.
func (s *Stamp) VerifyDetailed(ctx context.Context, hash string) (*VerificationResult, error) {
	response := s.response
	if s.client != nil && s.StampID != "" {
		if fresh, err := s.client.GetStamp(s.StampID, &GetStampOptions{Wait: BoolPtr(false), Context: ctx}); err == nil {
			response = fresh.response
		}
	}

	opts := &VerifyOptions{Chain: blockchain.Mainnet}
	if s.client != nil {
		opts.Chain = s.client.chain
		opts.RPCHTTPClient = s.client.rpcClient
	}
	return verifyResponse(ctx, hash, response, opts)
}

// VerifyOffline checks the leaf binding and the merkle path only (no network
// access, no on-chain check). A true result does NOT prove the root was ever
// anchored on-chain.
func (s *Stamp) VerifyOffline(hash string) (bool, error) {
	_, err := verifyResponse(context.Background(), hash, s.response, &VerifyOptions{SkipOnChain: true})
	if err != nil {
		if errors.Is(err, ErrHashMismatch) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func verifyResponse(ctx context.Context, hash string, response map[string]interface{}, opts *VerifyOptions) (*VerificationResult, error) {
	if _, ok := response["merkle_proof"].(map[string]interface{}); !ok {
		return nil, fmt.Errorf("no merkle proof available")
	}
	proof, err := ProofFromResponse(response)
	if err != nil {
		return nil, err
	}
	if serverHash, ok := response["hash"].(string); ok && serverHash != "" {
		h, herr := merkle.NormalizeHash(hash)
		sh, sherr := merkle.NormalizeHash(serverHash)
		if herr == nil && sherr == nil && h != sh {
			return nil, fmt.Errorf("%w: stamp is for hash %s", ErrHashMismatch, sh)
		}
	}
	return VerifyProof(ctx, hash, proof, opts)
}

// GetHash returns the hash that was submitted for timestamping (the "hash"
// field of the API response). For responses without it, the merkle proof's
// leaf_hash is returned for backward compatibility.
func (s *Stamp) GetHash() (string, error) {
	if h, ok := s.response["hash"].(string); ok && h != "" {
		return h, nil
	}
	merkleProofData, ok := s.response["merkle_proof"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("no merkle proof available")
	}

	leafHash, ok := merkleProofData["leaf_hash"].(string)
	if !ok {
		return "", fmt.Errorf("invalid leaf_hash in merkle proof")
	}

	return leafHash, nil
}

// GetNonce returns the server batch nonce used to build the merkle leaf.
func (s *Stamp) GetNonce() string {
	return stringField(s.response, "nonce")
}

// GetTxID returns the anchoring transaction hash, if confirmed.
func (s *Stamp) GetTxID() string {
	return stringField(s.response, "tx_id")
}

// GetMerkleRoot returns the merkle root, if batched.
func (s *Stamp) GetMerkleRoot() string {
	return stringField(s.response, "merkle_root")
}

// GetStatus returns the stamp status (pending, batched, confirmed, failed).
func (s *Stamp) GetStatus() string {
	return stringField(s.response, "status")
}

// GetStampedAt returns the time when this hash was stamped
func (s *Stamp) GetStampedAt() (time.Time, error) {
	timestampStr, ok := s.response["timestamp"].(string)
	if !ok {
		return time.Time{}, fmt.Errorf("no timestamp available")
	}

	stampedAt, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	return stampedAt, nil
}

// GetBlockchainInfo returns blockchain information for this stamp: the
// "blockchain_info" object if the server sent one, otherwise the network,
// tx_id, block_hash and merkle_root fields of a confirmed stamp.
func (s *Stamp) GetBlockchainInfo() (map[string]interface{}, error) {
	if raw, present := s.response["blockchain_info"]; present {
		blockchainInfo, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid blockchain info")
		}
		return blockchainInfo, nil
	}
	txID := stringField(s.response, "tx_id")
	if txID == "" {
		return nil, fmt.Errorf("no blockchain info available")
	}
	info := map[string]interface{}{"tx_id": txID}
	for _, k := range []string{"network", "block_hash", "merkle_root"} {
		if v := stringField(s.response, k); v != "" {
			info[k] = v
		}
	}
	return info, nil
}

// GetRawResponse returns the raw API response
func (s *Stamp) GetRawResponse() map[string]interface{} {
	return s.response
}

// ProofFromResponse converts a GET /stamp/{id} response into a types.Proof.
// The top-level batch "nonce" is copied into MerkleProof.Nonce. Fields with
// the wrong JSON type are reported as errors.
func ProofFromResponse(response map[string]interface{}) (*types.Proof, error) {
	proof := &types.Proof{
		Network:    stringField(response, "network"),
		TxID:       stringField(response, "tx_id"),
		BlockHash:  stringField(response, "block_hash"),
		Status:     stringField(response, "status"),
		MerkleRoot: stringField(response, "merkle_root"),
	}
	if bn, ok := response["block_number"].(float64); ok && bn >= 0 {
		proof.BlockNumber = uint64(bn)
	}

	raw, present := response["merkle_proof"]
	if !present || raw == nil {
		return proof, nil
	}
	mp, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid merkle_proof in response")
	}

	merkleProof := &types.MerkleProof{}
	if merkleProof.LeafHash, ok = mp["leaf_hash"].(string); !ok {
		return nil, fmt.Errorf("invalid leaf_hash in merkle proof")
	}
	if merkleProof.RootHash, ok = mp["root_hash"].(string); !ok {
		return nil, fmt.Errorf("invalid root_hash in merkle proof")
	}
	if v, present := mp["leaf_index"]; present {
		f, ok := v.(float64)
		if !ok || f < 0 || f != float64(int(f)) {
			return nil, fmt.Errorf("invalid leaf_index in merkle proof")
		}
		merkleProof.LeafIndex = int(f)
	}
	if v, present := mp["siblings"]; present && v != nil {
		list, ok := v.([]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid siblings in merkle proof")
		}
		merkleProof.Siblings = make([]string, len(list))
		for i, item := range list {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("invalid sibling at index %d", i)
			}
			merkleProof.Siblings[i] = str
		}
	}
	if v, present := mp["directions"]; present && v != nil {
		list, ok := v.([]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid directions in merkle proof")
		}
		merkleProof.Directions = make([]bool, len(list))
		for i, item := range list {
			b, ok := item.(bool)
			if !ok {
				return nil, fmt.Errorf("invalid direction at index %d", i)
			}
			merkleProof.Directions[i] = b
		}
	}
	merkleProof.Nonce = stringField(response, "nonce")
	if merkleProof.Nonce == "" {
		merkleProof.Nonce = stringField(mp, "nonce")
	}
	proof.MerkleProof = merkleProof
	return proof, nil
}

func stringField(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

// File-based utility functions

// CreateFileStamp creates a FileStamp structure from a file
func CreateFileStamp(filename string) (*types.FileStamp, error) {
	stampedHash, err := crypto.CreateStampedHash(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create stamped hash: %w", err)
	}

	return &types.FileStamp{
		Filename:  filename,
		Hash:      stampedHash.Hash,     // The timestamped hash (with nonce)
		FileHash:  stampedHash.FileHash, // Original file hash
		Nonce:     stampedHash.Nonce,    // Privacy nonce
		Algorithm: "SHA256",
		CreatedAt: time.Now(),
		Proofs:    []types.Proof{},
	}, nil
}

// LoadFileStamp loads a FileStamp from a JSON file
func LoadFileStamp(filename string) (*types.FileStamp, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var stamp types.FileStamp
	if err := json.Unmarshal(data, &stamp); err != nil {
		return nil, fmt.Errorf("failed to parse stamp: %w", err)
	}

	return &stamp, nil
}

// SaveFileStamp saves a FileStamp to a JSON file
func SaveFileStamp(stamp *types.FileStamp, filename string) error {
	data, err := json.MarshalIndent(stamp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal stamp: %w", err)
	}

	return os.WriteFile(filename, data, 0o644)
}

// UpdateFileStampWithBlockchainData fetches complete blockchain data from API and updates the FileStamp
func UpdateFileStampWithBlockchainData(stamp *types.FileStamp, client *Client) error {
	if stamp.StampID == "" {
		return fmt.Errorf("stamp ID is required to fetch blockchain data")
	}

	apiStamp, err := client.GetStamp(stamp.StampID, NoWait())
	if err != nil {
		return fmt.Errorf("failed to fetch stamp data from API: %w", err)
	}

	proof, err := ProofFromResponse(apiStamp.response)
	if err != nil {
		return fmt.Errorf("invalid stamp data from API: %w", err)
	}
	if proof.Network != "" && proof.TxID != "" {
		proof.StampedAt = stamp.CreatedAt
		stamp.Proofs = []types.Proof{*proof}
	}

	return nil
}

// VerifyFileStamp checks LOCALLY that a file matches its stamp file (file
// hash and privacy nonce). It does not verify the merkle proof or the
// blockchain anchor; use VerifyFileStampProof for that.
func VerifyFileStamp(filename, stampFile string) (bool, error) {
	stamp, err := LoadFileStamp(stampFile)
	if err != nil {
		return false, fmt.Errorf("failed to load stamp: %w", err)
	}
	return verifyFileAgainstStamp(filename, stamp)
}

func verifyFileAgainstStamp(filename string, stamp *types.FileStamp) (bool, error) {
	if stamp.Nonce != "" && stamp.FileHash != "" {
		stampedHash := &crypto.StampedHash{
			FileHash: stamp.FileHash,
			Nonce:    stamp.Nonce,
			Hash:     stamp.Hash,
		}
		if err := crypto.VerifyStampedHash(filename, stampedHash); err != nil {
			return false, nil // File doesn't match
		}
		return true, nil
	}
	// Legacy format without nonce
	hash, err := crypto.HashFile(filename)
	if err != nil {
		return false, fmt.Errorf("failed to hash file: %w", err)
	}
	return strings.EqualFold(hash, stamp.Hash), nil
}

// VerifyFileStampProof checks that filename matches stampFile and that the
// stored proof anchors the stamped hash on-chain (see VerifyProof).
func VerifyFileStampProof(ctx context.Context, filename, stampFile string, opts *VerifyOptions) (*VerificationResult, error) {
	stamp, err := LoadFileStamp(stampFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load stamp: %w", err)
	}
	ok, err := verifyFileAgainstStamp(filename, stamp)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: file does not match stamp file", ErrHashMismatch)
	}
	if len(stamp.Proofs) == 0 || stamp.Proofs[0].MerkleProof == nil {
		return nil, fmt.Errorf("stamp file has no merkle proof")
	}
	return VerifyProof(ctx, stamp.Hash, &stamp.Proofs[0], opts)
}

// CalculateFileHash calculates the SHA256 hash of a file
func CalculateFileHash(filename string) (string, error) {
	return crypto.HashFile(filename)
}

// CreateStampedHash creates a privacy-preserving stamped hash from a file
func CreateStampedHash(filename string) (*crypto.StampedHash, error) {
	return crypto.CreateStampedHash(filename)
}

// VerifyStampedHash verifies a file against a stamped hash structure
func VerifyStampedHash(filename string, stampedHash *crypto.StampedHash) error {
	return crypto.VerifyStampedHash(filename, stampedHash)
}
