// Package types provides data structures for BaseStamp timestamping operations.
//
// This package defines the core types used for file timestamping, proof
// verification, and API interactions with BaseStamp services.
package types

import (
	"time"
)

// FileStamp represents a timestamped file with cryptographic proof.
// This is the main structure created when stamping a file and stored
// in .basestamp proof files.
type FileStamp struct {
	Filename  string    `json:"filename"`   // Original filename
	Hash      string    `json:"hash"`       // The timestamped hash (with nonce) sent to server
	FileHash  string    `json:"file_hash"`  // Original file hash
	Nonce     string    `json:"nonce"`      // Privacy nonce
	StampID   string    `json:"stamp_id"`   // Unique stamp identifier from server
	Algorithm string    `json:"algorithm"`  // Hash algorithm used (typically "SHA256")
	CreatedAt time.Time `json:"created_at"` // When the stamp was created
	Proofs    []Proof   `json:"proofs"`     // Blockchain proofs
}

// Proof represents a complete blockchain proof for a timestamp.
// Contains all information needed to verify the timestamp on-chain.
type Proof struct {
	Network     string       `json:"network"`                // Blockchain network (e.g., "BASE Sepolia")
	TxID        string       `json:"tx_id"`                  // Transaction ID on blockchain
	BlockHash   string       `json:"block_hash"`             // Block hash containing the transaction
	BlockNumber uint64       `json:"block_number"`           // Block number for verification
	StampedAt   time.Time    `json:"stamped_at"`             // When the proof was created
	Status      string       `json:"status"`                 // Proof status ("confirmed", "pending", etc.)
	MerkleRoot  string       `json:"merkle_root"`            // The merkle root written to blockchain
	MerkleProof *MerkleProof `json:"merkle_proof,omitempty"` // Complete merkle proof data
}

// MerkleProof represents a complete merkle proof for blockchain verification.
// Contains all data needed to reconstruct the path from leaf to root.
//
// LeafHash = SHA256(utf8(Nonce + hash)) where hash is the submitted lowercase
// hex hash and Nonce the server batch nonce. Each parent is
// SHA256(min(a,b) || max(a,b)) over raw 32-byte nodes (sorted pair), so
// Directions are informational and do not affect the computed root.
type MerkleProof struct {
	LeafHash   string   `json:"leaf_hash"`   // SHA256(nonce + submitted hash), not the submitted hash itself
	LeafIndex  int      `json:"leaf_index"` // Position of leaf in the merkle tree
	Siblings   []string `json:"siblings"`   // Sibling hashes for proof path
	Directions []bool   `json:"directions"`  // true = sibling on the right (informational: pairs are sorted)
	RootHash   string   `json:"root_hash"`  // Expected merkle root (should match MerkleRoot)
	Nonce      string   `json:"nonce"`       // Server batch nonce (top-level "nonce" of the API response)
}

// CalendarRequest represents a request to timestamp a hash.
// Used when submitting hashes to the BaseStamp API.
type CalendarRequest struct {
	Hash      string `json:"hash"`                // SHA256 hash to timestamp
	Signature string `json:"signature,omitempty"` // Optional signature for authentication
}

// CalendarResponse represents a response from the calendar API.
// Returned when requesting timestamp information.
type CalendarResponse struct {
	Hash      string    `json:"hash"`              // The timestamped hash
	StampedAt time.Time `json:"stamped_at"`        // When the hash was stamped
	TxID      string    `json:"tx_id,omitempty"`   // Blockchain transaction ID
	Status    string    `json:"status"`            // Status of the timestamp
	Message   string    `json:"message,omitempty"` // Additional information
}

// StampResponse represents a response from the stamp API.
// Returned when submitting a hash for timestamping.
type StampResponse struct {
	StampID   string    `json:"stamp_id"`          // Unique identifier for this stamp
	Hash      string    `json:"hash"`              // The hash that was stamped
	StampedAt time.Time `json:"stamped_at"`        // When the stamp was created
	Status    string    `json:"status"`            // Current status
	Message   string    `json:"message,omitempty"` // Additional information
}

// Error represents a BaseStamp error
type Error struct {
	Message string
}

func (e *Error) Error() string {
	return e.Message
}

// NewError creates a new BaseStamp error
func NewError(message string) *Error {
	return &Error{Message: message}
}
