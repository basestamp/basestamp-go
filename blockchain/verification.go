// Package blockchain verifies BaseStamp merkle roots against the Basestamp
// contract on Base using plain JSON-RPC (no third-party explorer APIs).
//
// A root is considered anchored when ALL of the following hold for the
// anchoring transaction:
//
//  1. the RPC endpoint reports the expected chain id (eth_chainId);
//  2. the transaction receipt exists, has status 0x1 and was sent to the
//     Basestamp contract (eth_getTransactionReceipt);
//  3. the receipt contains a non-removed log emitted by the contract whose
//     topics are Stamped(bytes32 indexed hash, uint256 timestamp,
//     uint256 blockNumber, address indexed submitter) with hash == root
//     (and submitter == the expected signer, when configured);
//  4. the transaction calldata is stamp(bytes32) with the same root and the
//     sender is the expected signer, when configured
//     (eth_getTransactionByHash);
//  5. the block has at least MinConfirmations confirmations (eth_blockNumber).
//
// FindStampedRoot additionally offers an eth_getLogs based lookup that does not
// need a transaction hash.
package blockchain

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/basestamp/basestamp-go/merkle"
	"github.com/basestamp/basestamp-go/types"
)

const (
	// StampedEventTopic is keccak256("Stamped(bytes32,uint256,uint256,address)").
	StampedEventTopic = "0x88ad9da3b29de3590ad9ee465751a6e2a86d8174c41c6a8fabe9360b13deb600"
	// StampFunctionSelector is the first 4 bytes of keccak256("stamp(bytes32)").
	StampFunctionSelector = "dd89581f"

	// MaxRPCResponseBytes caps how much of an RPC response is read.
	MaxRPCResponseBytes = 4 << 20
)

// ChainConfig describes a Basestamp deployment.
type ChainConfig struct {
	Name            string // Network name as reported by the API, e.g. "BASE Mainnet"
	ChainID         uint64 // Expected EVM chain id
	RPCURL          string // JSON-RPC endpoint
	ContractAddress string // Basestamp contract (0x-prefixed)
	// SignerAddress, when non-empty, is the only accepted transaction sender /
	// Stamped submitter. Leave empty to accept any submitter.
	SignerAddress string
	// MinConfirmations is the minimum number of blocks (including the anchoring
	// block) required. 0 is treated as 1.
	MinConfirmations uint64
	// ExplorerTxURL is a printf pattern for a transaction explorer link.
	ExplorerTxURL string
}

// Mainnet is the production Basestamp deployment on Base mainnet.
var Mainnet = ChainConfig{
	Name:             "BASE Mainnet",
	ChainID:          8453,
	RPCURL:           "https://mainnet.base.org",
	ContractAddress:  "0x634494cB65B17163A4ca84378900Ff53A4Bba05C",
	SignerAddress:    "0x0a3861972b28e6be9fEB826dd809aEB4F473e753",
	MinConfirmations: 1,
	ExplorerTxURL:    "https://basescan.org/tx/%s",
}

// Sepolia is the Basestamp deployment on Base Sepolia testnet. The Sepolia
// contract is unrestricted (anyone can call stamp), so a successful Sepolia
// verification only proves that *someone* stamped the root.
var Sepolia = ChainConfig{
	Name:             "BASE Sepolia",
	ChainID:          84532,
	RPCURL:           "https://sepolia.base.org",
	ContractAddress:  "0x15Adb2cc1aEDB6610E1C801BE7E205be3A8De5d7",
	MinConfirmations: 1,
	ExplorerTxURL:    "https://sepolia.basescan.org/tx/%s",
}

// ConfigForNetwork returns the known deployment for an API network name.
func ConfigForNetwork(network string) (ChainConfig, error) {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "base mainnet", "base":
		return Mainnet, nil
	case "base sepolia":
		return Sepolia, nil
	default:
		return ChainConfig{}, fmt.Errorf("unsupported network: %q", network)
	}
}

// ExplorerURL returns a block explorer link for txID, or "" if unknown.
func (c ChainConfig) ExplorerURL(txID string) string {
	if c.ExplorerTxURL == "" || txID == "" {
		return ""
	}
	return fmt.Sprintf(c.ExplorerTxURL, txID)
}

// ErrNotAnchored is wrapped by every error that means "the chain does not
// show this root as stamped by the contract" (as opposed to RPC/transport
// failures).
var ErrNotAnchored = errors.New("merkle root is not anchored on-chain")

func notAnchored(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrNotAnchored, fmt.Sprintf(format, args...))
}

// Anchor describes an on-chain Stamped event that anchors a merkle root.
type Anchor struct {
	Root           string    // lowercase hex, no 0x
	TxHash         string    // 0x-prefixed
	BlockNumber    uint64    // block containing the transaction
	BlockHash      string    // 0x-prefixed
	BlockTimestamp time.Time // block.timestamp emitted by the Stamped event
	Submitter      string    // 0x-prefixed lowercase address
	Confirmations  uint64    // latest block - BlockNumber + 1
	ChainID        uint64
	Contract       string
}

// BlockchainVerifier handles verification against a Basestamp deployment.
type BlockchainVerifier struct {
	httpClient *http.Client
	config     *ChainConfig // nil = derive from the proof's network name
	retries    int
}

// NewVerifier creates a verifier that picks the deployment from the proof's
// network name (see ConfigForNetwork). Prefer NewVerifierForChain to pin the
// expected chain so a server cannot redirect verification to another network.
func NewVerifier() *BlockchainVerifier {
	return &BlockchainVerifier{httpClient: defaultHTTPClient(), retries: 4}
}

// NewVerifierForChain creates a verifier pinned to cfg.
func NewVerifierForChain(cfg ChainConfig) *BlockchainVerifier {
	v := NewVerifier()
	v.config = &cfg
	return v
}

// WithHTTPClient sets the HTTP client used for JSON-RPC calls.
func (v *BlockchainVerifier) WithHTTPClient(c *http.Client) *BlockchainVerifier {
	if c != nil {
		v.httpClient = c
	}
	return v
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func (v *BlockchainVerifier) configFor(network string) (ChainConfig, error) {
	if v.config != nil {
		return *v.config, nil
	}
	return ConfigForNetwork(network)
}

// VerifyProof checks that proof.MerkleProof is internally consistent, that its
// root equals proof.MerkleRoot, and that the root was stamped on-chain by
// proof.TxID. It does not bind the leaf to a user hash; see
// basestamp.Stamp.Verify for the complete check.
func (v *BlockchainVerifier) VerifyProof(proof *types.Proof) error {
	return v.VerifyProofContext(context.Background(), proof)
}

// VerifyProofContext is VerifyProof with a context.
func (v *BlockchainVerifier) VerifyProofContext(ctx context.Context, proof *types.Proof) error {
	if proof == nil {
		return fmt.Errorf("proof cannot be nil")
	}
	if proof.TxID == "" {
		return fmt.Errorf("transaction ID is required for blockchain verification")
	}
	if proof.MerkleProof == nil {
		return fmt.Errorf("merkle proof is required for verification")
	}
	if proof.MerkleRoot == "" {
		return fmt.Errorf("merkle root is required for verification")
	}

	if !merkle.VerifyProof(&merkle.Proof{
		LeafHash:   proof.MerkleProof.LeafHash,
		LeafIndex:  proof.MerkleProof.LeafIndex,
		Siblings:   proof.MerkleProof.Siblings,
		Directions: proof.MerkleProof.Directions,
		RootHash:   proof.MerkleProof.RootHash,
	}) {
		return fmt.Errorf("merkle proof verification failed: path does not reconstruct root_hash")
	}

	if !sameHash(proof.MerkleProof.RootHash, proof.MerkleRoot) {
		return fmt.Errorf("merkle proof root mismatch: proof_root=%s, claimed_root=%s",
			proof.MerkleProof.RootHash, proof.MerkleRoot)
	}

	cfg, err := v.configFor(proof.Network)
	if err != nil {
		return err
	}
	if v.config != nil && proof.Network != "" {
		if claimed, cerr := ConfigForNetwork(proof.Network); cerr == nil && claimed.ChainID != cfg.ChainID {
			return fmt.Errorf("proof is for network %q but verifier is pinned to %q", proof.Network, cfg.Name)
		}
	}

	_, err = v.VerifyRootOnChain(ctx, cfg, proof.TxID, proof.MerkleRoot)
	return err
}

// VerifyRootOnChain confirms that transaction txID on cfg's chain called the
// Basestamp contract and emitted Stamped(root). See the package documentation
// for the exact checks.
func (v *BlockchainVerifier) VerifyRootOnChain(ctx context.Context, cfg ChainConfig, txID, root string) (*Anchor, error) {
	root, err := merkle.NormalizeHash(root)
	if err != nil {
		return nil, fmt.Errorf("merkle root: %w", err)
	}
	txID, err = normalizeTxHash(txID)
	if err != nil {
		return nil, err
	}
	if cfg.RPCURL == "" || !isAddress(cfg.ContractAddress) {
		return nil, fmt.Errorf("chain config requires an RPC URL and a contract address")
	}
	if cfg.SignerAddress != "" && !isAddress(cfg.SignerAddress) {
		return nil, fmt.Errorf("invalid signer address %q", cfg.SignerAddress)
	}
	contract := strings.ToLower(cfg.ContractAddress)
	signer := strings.ToLower(cfg.SignerAddress)

	// 1. Chain id.
	var chainIDHex string
	if err := v.call(ctx, cfg.RPCURL, "eth_chainId", []interface{}{}, &chainIDHex); err != nil {
		return nil, err
	}
	chainID, err := parseQuantity(chainIDHex)
	if err != nil {
		return nil, fmt.Errorf("eth_chainId: %w", err)
	}
	if cfg.ChainID != 0 && chainID != cfg.ChainID {
		return nil, fmt.Errorf("RPC endpoint is on chain %d, expected %d", chainID, cfg.ChainID)
	}

	// 2. Receipt.
	var receipt *rpcReceipt
	if err := v.call(ctx, cfg.RPCURL, "eth_getTransactionReceipt", []interface{}{txID}, &receipt); err != nil {
		return nil, err
	}
	if receipt == nil {
		return nil, notAnchored("transaction %s not found (or not yet mined)", txID)
	}
	if !strings.EqualFold(receipt.TransactionHash, txID) {
		return nil, fmt.Errorf("RPC returned receipt for %s, asked for %s", receipt.TransactionHash, txID)
	}
	if status, err := parseQuantity(receipt.Status); err != nil || status != 1 {
		return nil, notAnchored("transaction %s reverted or has no success status", txID)
	}
	if !strings.EqualFold(receipt.To, contract) {
		return nil, notAnchored("transaction was sent to %s, not the Basestamp contract %s", receipt.To, cfg.ContractAddress)
	}
	blockNumber, err := parseQuantity(receipt.BlockNumber)
	if err != nil {
		return nil, fmt.Errorf("receipt blockNumber: %w", err)
	}

	// 3. Stamped event for this root.
	anchor, err := findStampedLog(receipt.Logs, contract, root, signer)
	if err != nil {
		return nil, err
	}
	if anchor.BlockNumber != blockNumber {
		return nil, notAnchored("Stamped event block number %d != receipt block %d", anchor.BlockNumber, blockNumber)
	}
	anchor.TxHash = txID
	anchor.BlockNumber = blockNumber
	anchor.BlockHash = receipt.BlockHash
	anchor.ChainID = chainID
	anchor.Contract = contract

	// 4. Transaction calldata and sender.
	var tx *rpcTransaction
	if err := v.call(ctx, cfg.RPCURL, "eth_getTransactionByHash", []interface{}{txID}, &tx); err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, notAnchored("transaction %s not found", txID)
	}
	if !strings.EqualFold(tx.To, contract) {
		return nil, notAnchored("transaction is not addressed to the Basestamp contract")
	}
	calldataRoot, err := parseStampCalldata(tx.Input)
	if err != nil {
		return nil, notAnchored("%v", err)
	}
	if calldataRoot != root {
		return nil, notAnchored("stamp() argument %s does not match root %s", calldataRoot, root)
	}
	if signer != "" && !strings.EqualFold(tx.From, signer) {
		return nil, notAnchored("transaction sender %s is not the Basestamp signer %s", tx.From, cfg.SignerAddress)
	}

	// 5. Confirmations.
	var latestHex string
	if err := v.call(ctx, cfg.RPCURL, "eth_blockNumber", []interface{}{}, &latestHex); err != nil {
		return nil, err
	}
	latest, err := parseQuantity(latestHex)
	if err != nil {
		return nil, fmt.Errorf("eth_blockNumber: %w", err)
	}
	if latest >= blockNumber {
		anchor.Confirmations = latest - blockNumber + 1
	}
	minConf := cfg.MinConfirmations
	if minConf == 0 {
		minConf = 1
	}
	if anchor.Confirmations < minConf {
		return nil, notAnchored("only %d confirmations, need %d", anchor.Confirmations, minConf)
	}
	return anchor, nil
}

// FindStampedRoot searches the contract's Stamped events for root using
// eth_getLogs over [fromBlock, toBlock] (toBlock 0 = "latest"). Public RPCs
// limit the block range (and https://mainnet.base.org rejects eth_getLogs
// entirely), so keep the range small and use an RPC that serves logs, e.g.
// cfg.RPCURL = "https://base-rpc.publicnode.com". It returns ErrNotAnchored
// if no matching event is found.
func (v *BlockchainVerifier) FindStampedRoot(ctx context.Context, cfg ChainConfig, root string, fromBlock, toBlock uint64) (*Anchor, error) {
	root, err := merkle.NormalizeHash(root)
	if err != nil {
		return nil, fmt.Errorf("merkle root: %w", err)
	}
	if !isAddress(cfg.ContractAddress) {
		return nil, fmt.Errorf("invalid contract address %q", cfg.ContractAddress)
	}
	var chainIDHex string
	if err := v.call(ctx, cfg.RPCURL, "eth_chainId", []interface{}{}, &chainIDHex); err != nil {
		return nil, err
	}
	if chainID, err := parseQuantity(chainIDHex); err != nil || (cfg.ChainID != 0 && chainID != cfg.ChainID) {
		return nil, fmt.Errorf("RPC endpoint chain id %q, expected %d", chainIDHex, cfg.ChainID)
	}
	to := "latest"
	if toBlock != 0 {
		to = fmt.Sprintf("0x%x", toBlock)
	}
	topics := []interface{}{StampedEventTopic, "0x" + root}
	if cfg.SignerAddress != "" {
		topics = append(topics, addressTopic(strings.ToLower(cfg.SignerAddress)))
	}
	filter := map[string]interface{}{
		"address":   cfg.ContractAddress,
		"fromBlock": fmt.Sprintf("0x%x", fromBlock),
		"toBlock":   to,
		"topics":    topics,
	}
	var logs []rpcLog
	if err := v.call(ctx, cfg.RPCURL, "eth_getLogs", []interface{}{filter}, &logs); err != nil {
		return nil, err
	}
	anchor, err := findStampedLog(logs, strings.ToLower(cfg.ContractAddress), root, strings.ToLower(cfg.SignerAddress))
	if err != nil {
		return nil, err
	}
	anchor.ChainID = cfg.ChainID
	anchor.Contract = strings.ToLower(cfg.ContractAddress)
	return anchor, nil
}

func findStampedLog(logs []rpcLog, contract, root, signer string) (*Anchor, error) {
	for _, l := range logs {
		if l.Removed || !strings.EqualFold(l.Address, contract) || len(l.Topics) < 3 {
			continue
		}
		if !strings.EqualFold(l.Topics[0], StampedEventTopic) {
			continue
		}
		if !strings.EqualFold(strings.TrimPrefix(l.Topics[1], "0x"), root) {
			continue
		}
		submitter, err := topicAddress(l.Topics[2])
		if err != nil {
			continue
		}
		if signer != "" && submitter != signer {
			continue
		}
		a := &Anchor{Root: root, Submitter: submitter, TxHash: l.TransactionHash, BlockHash: l.BlockHash}
		if bn, err := parseQuantity(l.BlockNumber); err == nil {
			a.BlockNumber = bn
		}
		// data = abi.encode(uint256 timestamp, uint256 blockNumber)
		data := strings.TrimPrefix(l.Data, "0x")
		if len(data) >= 128 {
			if ts, ok := new(big.Int).SetString(data[:64], 16); ok && ts.IsInt64() {
				a.BlockTimestamp = time.Unix(ts.Int64(), 0).UTC()
			}
			bn, ok := new(big.Int).SetString(data[64:128], 16)
			if !ok || !bn.IsUint64() || (a.BlockNumber != 0 && bn.Uint64() != a.BlockNumber) {
				continue // event's blockNumber disagrees with the log's block
			}
			a.BlockNumber = bn.Uint64()
		}
		return a, nil
	}
	if signer != "" {
		return nil, notAnchored("no Stamped(%s) event from contract %s submitted by %s", root, contract, signer)
	}
	return nil, notAnchored("no Stamped(%s) event from contract %s", root, contract)
}

func parseStampCalldata(input string) (string, error) {
	data := strings.ToLower(strings.TrimPrefix(input, "0x"))
	if len(data) != 8+64 {
		return "", fmt.Errorf("calldata has %d hex chars, expected stamp(bytes32) (72)", len(data))
	}
	if data[:8] != StampFunctionSelector {
		return "", fmt.Errorf("calldata selector 0x%s is not stamp(bytes32)", data[:8])
	}
	if _, err := hex.DecodeString(data[8:]); err != nil {
		return "", fmt.Errorf("calldata is not hex: %w", err)
	}
	return data[8:], nil
}

// JSON-RPC plumbing.

type rpcLog struct {
	Address         string   `json:"address"`
	Topics          []string `json:"topics"`
	Data            string   `json:"data"`
	BlockNumber     string   `json:"blockNumber"`
	BlockHash       string   `json:"blockHash"`
	TransactionHash string   `json:"transactionHash"`
	Removed         bool     `json:"removed"`
}

type rpcReceipt struct {
	TransactionHash string   `json:"transactionHash"`
	Status          string   `json:"status"`
	To              string   `json:"to"`
	From            string   `json:"from"`
	BlockNumber     string   `json:"blockNumber"`
	BlockHash       string   `json:"blockHash"`
	Logs            []rpcLog `json:"logs"`
}

type rpcTransaction struct {
	Hash  string `json:"hash"`
	From  string `json:"from"`
	To    string `json:"to"`
	Input string `json:"input"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// RPCError is returned when the JSON-RPC endpoint reports an error.
type RPCError struct {
	Method  string
	Code    int
	Message string
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("RPC %s error %d: %s", e.Method, e.Code, e.Message)
}

func (v *BlockchainVerifier) call(ctx context.Context, url, method string, params []interface{}, out interface{}) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var lastErr error
	attempts := v.retries
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(1<<(i-1)) * time.Second):
			}
		}
		retry, err := v.callOnce(ctx, url, method, params, out)
		if err == nil {
			return nil
		}
		lastErr = err
		if !retry {
			break
		}
	}
	return lastErr
}

func (v *BlockchainVerifier) callOnce(ctx context.Context, url, method string, params []interface{}, out interface{}) (retry bool, err error) {
	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("RPC %s: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return ctx.Err() == nil, fmt.Errorf("RPC %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxRPCResponseBytes+1))
	if err != nil {
		return true, fmt.Errorf("RPC %s: reading response: %w", method, err)
	}
	if len(raw) > MaxRPCResponseBytes {
		return false, fmt.Errorf("RPC %s: response exceeds %d bytes", method, MaxRPCResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return retry, fmt.Errorf("RPC %s: HTTP %d: %s", method, resp.StatusCode, truncate(string(raw), 200))
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return false, fmt.Errorf("RPC %s: invalid JSON response: %w", method, err)
	}
	if envelope.Error != nil {
		msg := strings.ToLower(envelope.Error.Message)
		retry := strings.Contains(msg, "limit") || strings.Contains(msg, "rate") || strings.Contains(msg, "timeout")
		return retry, &RPCError{Method: method, Code: envelope.Error.Code, Message: envelope.Error.Message}
	}
	if len(envelope.Result) == 0 {
		return false, fmt.Errorf("RPC %s: response has no result", method)
	}
	if err := json.Unmarshal(envelope.Result, out); err != nil {
		return false, fmt.Errorf("RPC %s: unexpected result: %w", method, err)
	}
	return false, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func parseQuantity(q string) (uint64, error) {
	s := strings.TrimPrefix(strings.ToLower(q), "0x")
	if s == "" || len(s) > 16 {
		return 0, fmt.Errorf("invalid quantity %q", q)
	}
	n, ok := new(big.Int).SetString(s, 16)
	if !ok || !n.IsUint64() {
		return 0, fmt.Errorf("invalid quantity %q", q)
	}
	return n.Uint64(), nil
}

func normalizeTxHash(txID string) (string, error) {
	h, err := merkle.NormalizeHash(txID)
	if err != nil {
		return "", fmt.Errorf("invalid transaction hash %q: %w", txID, err)
	}
	return "0x" + h, nil
}

func isAddress(a string) bool {
	s := strings.TrimPrefix(strings.ToLower(a), "0x")
	if len(s) != 40 || !strings.HasPrefix(strings.ToLower(a), "0x") {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func addressTopic(addr string) string {
	return "0x" + strings.Repeat("0", 24) + strings.TrimPrefix(addr, "0x")
}

func topicAddress(topic string) (string, error) {
	t := strings.ToLower(strings.TrimPrefix(topic, "0x"))
	if len(t) != 64 || t[:24] != strings.Repeat("0", 24) {
		return "", fmt.Errorf("topic %q is not an address", topic)
	}
	return "0x" + t[24:], nil
}

func sameHash(a, b string) bool {
	na, err1 := merkle.NormalizeHash(a)
	nb, err2 := merkle.NormalizeHash(b)
	return err1 == nil && err2 == nil && na == nb
}
