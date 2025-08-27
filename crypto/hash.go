// Package crypto provides SHA256 hashing utilities and privacy-preserving
// stamped hash functionality for BaseStamp timestamping.
//
// This package implements the OpenTimestamps-style privacy model where
// file hashes are combined with random nonces before being submitted
// for timestamping, preventing rainbow table attacks while maintaining
// cryptographic integrity.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// HashFile computes the SHA256 hash of a file and returns it as a hex string.
func HashFile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to hash file: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// HashBytes computes the SHA256 hash of byte data and returns it as a hex string.
func HashBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// HashString computes the SHA256 hash of a string and returns it as a hex string.
func HashString(s string) string {
	return HashBytes([]byte(s))
}

// ValidateHash checks if a string is a valid 64-character hex hash.
func ValidateHash(hash string) error {
	if len(hash) != 64 {
		return fmt.Errorf("invalid hash length: expected 64 hex characters, got %d", len(hash))
	}
	_, err := hex.DecodeString(hash)
	if err != nil {
		return fmt.Errorf("invalid hex hash: %w", err)
	}
	return nil
}

// StampedHash represents a file hash with privacy nonce like OpenTimestamps.
// This structure prevents rainbow table attacks by combining the original
// file hash with a random nonce before timestamping.
type StampedHash struct {
	FileHash string `json:"file_hash"`     // Original file hash
	Nonce    string `json:"nonce"`         // Random nonce for privacy
	Hash     string `json:"hash"`          // Final hash sent to server (SHA256(file_hash + nonce))
}

// CreateStampedHash creates a stamped hash with nonce for privacy.
// This follows OpenTimestamps pattern: hash = SHA256(file_hash + nonce)
// The nonce provides privacy protection while maintaining verifiability.
func CreateStampedHash(filename string) (*StampedHash, error) {
	// First, hash the file contents
	fileHash, err := HashFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to hash file: %w", err)
	}
	
	// Generate a random 16-byte nonce for privacy
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)
	
	// Create the final hash: SHA256(file_hash + nonce)
	finalHash := HashString(fileHash + nonceHex)
	
	return &StampedHash{
		FileHash: fileHash,
		Nonce:    nonceHex,
		Hash:     finalHash,
	}, nil
}

// VerifyStampedHash verifies that the given file matches the stamped hash.
// It recomputes the file hash and validates it against the stamped hash.
func VerifyStampedHash(filename string, sh *StampedHash) error {
	// Hash the file
	fileHash, err := HashFile(filename)
	if err != nil {
		return fmt.Errorf("failed to hash file: %w", err)
	}
	
	// Check if file hash matches
	if fileHash != sh.FileHash {
		return fmt.Errorf("file hash mismatch: expected %s, got %s", sh.FileHash, fileHash)
	}
	
	// Recreate the final hash
	expectedFinalHash := HashString(sh.FileHash + sh.Nonce)
	if expectedFinalHash != sh.Hash {
		return fmt.Errorf("stamped hash verification failed")
	}
	
	return nil
}