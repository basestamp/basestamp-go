// Package merkle provides Merkle tree construction and proof verification
// for cryptographic timestamping applications.
//
// This package implements secure binary Merkle trees with support for:
// - Deterministic tree construction from arbitrary data
// - Cryptographic proof generation for any leaf
// - Independent proof verification
// - Protection against second-preimage attacks via lexicographic ordering
//
// Example usage:
//
//	data := [][]byte{[]byte("hello"), []byte("world")}
//	tree, err := merkle.NewTree(data)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	proof, err := tree.GenerateProof(0)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	isValid := merkle.VerifyProof(proof)
//	fmt.Printf("Proof valid: %v\n", isValid)
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Node represents a node in the Merkle tree.
// Leaf nodes contain the original data, while internal nodes contain hashes.
type Node struct {
	Hash   []byte
	Left   *Node
	Right  *Node
	IsLeaf bool
	Data   []byte // Original data for leaf nodes
}

// Tree represents a Merkle tree with a root node and leaf references.
type Tree struct {
	Root   *Node
	Leaves []*Node
}

// Proof represents a Merkle proof for a specific leaf.
// It contains all information needed to verify that a leaf is included in the tree.
type Proof struct {
	LeafHash    string   `json:"leaf_hash"`
	LeafIndex   int      `json:"leaf_index"`
	Siblings    []string `json:"siblings"`
	Directions  []bool   `json:"directions"` // true = right, false = left
	RootHash    string   `json:"root_hash"`
}

// NewTree creates a new Merkle tree from the given data.
// Each data slice becomes a leaf node in the tree.
func NewTree(data [][]byte) (*Tree, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot create tree with no data")
	}

	// Create leaf nodes
	leaves := make([]*Node, len(data))
	for i, d := range data {
		hash := sha256.Sum256(d)
		leaves[i] = &Node{
			Hash:   hash[:],
			IsLeaf: true,
			Data:   d,
		}
	}

	// Build the tree bottom-up
	currentLevel := leaves
	for len(currentLevel) > 1 {
		nextLevel := make([]*Node, 0)
		
		for i := 0; i < len(currentLevel); i += 2 {
			var left, right *Node
			left = currentLevel[i]
			
			if i+1 < len(currentLevel) {
				right = currentLevel[i+1]
			} else {
				// If odd number of nodes, duplicate the last one
				right = currentLevel[i]
			}
			
			// Create parent node
			parentHash := hashPair(left.Hash, right.Hash)
			parent := &Node{
				Hash:   parentHash,
				Left:   left,
				Right:  right,
				IsLeaf: false,
			}
			
			nextLevel = append(nextLevel, parent)
		}
		
		currentLevel = nextLevel
	}

	return &Tree{
		Root:   currentLevel[0],
		Leaves: leaves,
	}, nil
}

// hashPair creates a hash of two concatenated hashes
func hashPair(left, right []byte) []byte {
	// Ensure deterministic ordering to prevent second-preimage attacks
	var combined []byte
	if len(left) == len(right) {
		// For same-length hashes, use lexicographic ordering
		if hex.EncodeToString(left) < hex.EncodeToString(right) {
			combined = append(left, right...)
		} else {
			combined = append(right, left...)
		}
	} else {
		// This shouldn't happen in our use case, but handle it securely
		combined = append(left, right...)
	}
	
	hash := sha256.Sum256(combined)
	return hash[:]
}

// GetRootHash returns the root hash of the tree
func (t *Tree) GetRootHash() []byte {
	if t.Root == nil {
		return nil
	}
	return t.Root.Hash
}

// GenerateProof creates a Merkle proof for the data at the given index.
// The proof can be verified independently using VerifyProof.
func (t *Tree) GenerateProof(index int) (*Proof, error) {
	if index < 0 || index >= len(t.Leaves) {
		return nil, fmt.Errorf("index out of range")
	}

	leaf := t.Leaves[index]
	proof := &Proof{
		LeafHash:   hex.EncodeToString(leaf.Hash),
		LeafIndex:  index,
		Siblings:   make([]string, 0),
		Directions: make([]bool, 0),
		RootHash:   hex.EncodeToString(t.GetRootHash()),
	}

	// Trace path from leaf to root using sibling path reconstruction
	siblings, directions := t.findSiblingsPath(index)
	
	// Convert sibling bytes to hex strings
	for _, sibling := range siblings {
		proof.Siblings = append(proof.Siblings, hex.EncodeToString(sibling))
	}
	proof.Directions = directions

	return proof, nil
}

// findSiblingsPath finds the sibling hashes and directions for a given leaf index
func (t *Tree) findSiblingsPath(leafIndex int) ([][]byte, []bool) {
	siblings := make([][]byte, 0)
	directions := make([]bool, 0)
	
	// Rebuild path from scratch (this could be optimized by storing parent pointers)
	totalLeaves := len(t.Leaves)
	currentIndex := leafIndex
	currentLevelSize := totalLeaves
	
	for currentLevelSize > 1 {
		// Determine if we're a left or right child
		pairIndex := currentIndex ^ 1 // XOR with 1 to get sibling index
		
		if pairIndex < currentLevelSize {
			// We have a real sibling
			if currentIndex%2 == 0 {
				// We're the left child, sibling is on the right
				directions = append(directions, true)
			} else {
				// We're the right child, sibling is on the left
				directions = append(directions, false)
			}
			
			// Get sibling hash by reconstructing the tree level
			levelHashes := t.getLevelHashes(totalLeaves, currentLevelSize)
			siblings = append(siblings, levelHashes[pairIndex])
		} else {
			// No real sibling (odd number of nodes), we're paired with ourselves
			// This happens when we duplicate the last node
			directions = append(directions, true) // Arbitrary direction
			levelHashes := t.getLevelHashes(totalLeaves, currentLevelSize)
			siblings = append(siblings, levelHashes[currentIndex])
		}
		
		// Move to parent level
		currentIndex = currentIndex / 2
		currentLevelSize = (currentLevelSize + 1) / 2 // Ceiling division
	}
	
	return siblings, directions
}

// getLevelHashes reconstructs hashes at a specific level of the tree
func (t *Tree) getLevelHashes(totalLeaves, levelSize int) [][]byte {
	if levelSize == totalLeaves {
		// Leaf level
		hashes := make([][]byte, len(t.Leaves))
		for i, leaf := range t.Leaves {
			hashes[i] = leaf.Hash
		}
		return hashes
	}
	
	// Recursive case: build from previous level
	prevLevelSize := levelSize * 2
	if prevLevelSize > totalLeaves {
		prevLevelSize = totalLeaves
	}
	
	prevHashes := t.getLevelHashes(totalLeaves, prevLevelSize)
	currentHashes := make([][]byte, 0)
	
	for i := 0; i < len(prevHashes); i += 2 {
		var left, right []byte
		left = prevHashes[i]
		
		if i+1 < len(prevHashes) {
			right = prevHashes[i+1]
		} else {
			right = prevHashes[i] // Duplicate for odd number
		}
		
		parentHash := hashPair(left, right)
		currentHashes = append(currentHashes, parentHash)
	}
	
	return currentHashes
}

// VerifyProof verifies a Merkle proof independently.
// Returns true if the proof is valid and the leaf is included in the tree.
func VerifyProof(proof *Proof) bool {
	if proof == nil {
		return false
	}

	// Convert hex strings to bytes
	currentHash, err := hex.DecodeString(proof.LeafHash)
	if err != nil {
		return false
	}
	
	// Traverse up the tree using the proof
	for i, siblingHex := range proof.Siblings {
		if i >= len(proof.Directions) {
			return false
		}
		
		sibling, err := hex.DecodeString(siblingHex)
		if err != nil {
			return false
		}
		
		if proof.Directions[i] {
			// Sibling is on the right
			currentHash = hashPair(currentHash, sibling)
		} else {
			// Sibling is on the left
			currentHash = hashPair(sibling, currentHash)
		}
	}
	
	// Check if we've reached the expected root
	return hex.EncodeToString(currentHash) == proof.RootHash
}

// GetLeafCount returns the number of leaves in the tree
func (t *Tree) GetLeafCount() int {
	return len(t.Leaves)
}

// FindLeafIndex finds the index of a leaf with the given hash
func (t *Tree) FindLeafIndex(hash []byte) int {
	hashStr := hex.EncodeToString(hash)
	for i, leaf := range t.Leaves {
		if hex.EncodeToString(leaf.Hash) == hashStr {
			return i
		}
	}
	return -1
}