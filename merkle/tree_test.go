package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestNewTree(t *testing.T) {
	// Test creating a tree with sample data
	data := [][]byte{
		[]byte("test1"),
		[]byte("test2"),
		[]byte("test3"),
		[]byte("test4"),
	}

	tree, err := NewTree(data)
	if err != nil {
		t.Fatalf("Failed to create tree: %v", err)
	}

	if tree.Root == nil {
		t.Fatal("Tree root is nil")
	}

	if len(tree.Leaves) != 4 {
		t.Fatalf("Expected 4 leaves, got %d", len(tree.Leaves))
	}

	// Test root hash is not empty
	rootHash := tree.GetRootHash()
	if len(rootHash) == 0 {
		t.Fatal("Root hash is empty")
	}
}

func TestGenerateProof(t *testing.T) {
	// Create a tree with known data
	data := [][]byte{
		[]byte("test1"),
		[]byte("test2"),
		[]byte("test3"),
		[]byte("test4"),
	}

	tree, err := NewTree(data)
	if err != nil {
		t.Fatalf("Failed to create tree: %v", err)
	}

	// Generate proof for index 0
	proof, err := tree.GenerateProof(0)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Verify proof fields
	if proof.LeafIndex != 0 {
		t.Errorf("Expected leaf index 0, got %d", proof.LeafIndex)
	}

	if proof.LeafHash == "" {
		t.Error("Leaf hash is empty")
	}

	if proof.RootHash == "" {
		t.Error("Root hash is empty")
	}

	if len(proof.Siblings) == 0 {
		t.Error("Siblings array is empty")
	}

	if len(proof.Directions) == 0 {
		t.Error("Directions array is empty")
	}

	// Verify all sibling hashes are valid hex
	for i, sibling := range proof.Siblings {
		if _, err := hex.DecodeString(sibling); err != nil {
			t.Errorf("Invalid hex in sibling %d: %v", i, err)
		}
	}

	// Verify leaf hash is valid hex
	if _, err := hex.DecodeString(proof.LeafHash); err != nil {
		t.Errorf("Invalid hex in leaf hash: %v", err)
	}

	// Verify root hash is valid hex
	if _, err := hex.DecodeString(proof.RootHash); err != nil {
		t.Errorf("Invalid hex in root hash: %v", err)
	}
}

func TestVerifyProof(t *testing.T) {
	// Create a tree with known data
	data := [][]byte{
		[]byte("test1"),
		[]byte("test2"),
		[]byte("test3"),
		[]byte("test4"),
	}

	tree, err := NewTree(data)
	if err != nil {
		t.Fatalf("Failed to create tree: %v", err)
	}

	// Test all leaf proofs
	for i := 0; i < len(data); i++ {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			t.Fatalf("Failed to generate proof for index %d: %v", i, err)
		}

		// Verify the proof
		if !VerifyProof(proof) {
			t.Errorf("Proof verification failed for index %d", i)
		}
	}
}

func TestVerifyProofInvalidData(t *testing.T) {
	// Test with nil proof
	if VerifyProof(nil) {
		t.Error("Nil proof should not verify")
	}

	// Test with invalid hex in leaf hash
	invalidProof := &Proof{
		LeafHash:   "invalid_hex",
		LeafIndex:  0,
		Siblings:   []string{"abcd1234"},
		Directions: []bool{true},
		RootHash:   "deadbeef",
	}

	if VerifyProof(invalidProof) {
		t.Error("Invalid hex proof should not verify")
	}

	// Test with invalid hex in siblings
	invalidProof2 := &Proof{
		LeafHash:   "abcd1234",
		LeafIndex:  0,
		Siblings:   []string{"invalid_hex"},
		Directions: []bool{true},
		RootHash:   "deadbeef",
	}

	if VerifyProof(invalidProof2) {
		t.Error("Invalid hex sibling should not verify")
	}

	// Test with mismatched directions length
	invalidProof3 := &Proof{
		LeafHash:   "abcd1234",
		LeafIndex:  0,
		Siblings:   []string{"deadbeef", "cafebabe"},
		Directions: []bool{true}, // Should have 2 directions
		RootHash:   "deadbeef",
	}

	if VerifyProof(invalidProof3) {
		t.Error("Mismatched directions length should not verify")
	}
}

func TestProofJSONSerialization(t *testing.T) {
	// Create a tree with known data
	data := [][]byte{
		[]byte("test1"),
		[]byte("test2"),
		[]byte("test3"),
		[]byte("test4"),
	}

	tree, err := NewTree(data)
	if err != nil {
		t.Fatalf("Failed to create tree: %v", err)
	}

	// Generate proof
	proof, err := tree.GenerateProof(0)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("Failed to marshal proof to JSON: %v", err)
	}

	// Unmarshal from JSON
	var deserializedProof Proof
	if err := json.Unmarshal(jsonData, &deserializedProof); err != nil {
		t.Fatalf("Failed to unmarshal proof from JSON: %v", err)
	}

	// Verify all fields match
	if deserializedProof.LeafHash != proof.LeafHash {
		t.Errorf("Leaf hash mismatch: expected %s, got %s", proof.LeafHash, deserializedProof.LeafHash)
	}

	if deserializedProof.LeafIndex != proof.LeafIndex {
		t.Errorf("Leaf index mismatch: expected %d, got %d", proof.LeafIndex, deserializedProof.LeafIndex)
	}

	if deserializedProof.RootHash != proof.RootHash {
		t.Errorf("Root hash mismatch: expected %s, got %s", proof.RootHash, deserializedProof.RootHash)
	}

	if len(deserializedProof.Siblings) != len(proof.Siblings) {
		t.Errorf("Siblings length mismatch: expected %d, got %d", len(proof.Siblings), len(deserializedProof.Siblings))
	}

	for i, sibling := range deserializedProof.Siblings {
		if sibling != proof.Siblings[i] {
			t.Errorf("Sibling %d mismatch: expected %s, got %s", i, proof.Siblings[i], sibling)
		}
	}

	if len(deserializedProof.Directions) != len(proof.Directions) {
		t.Errorf("Directions length mismatch: expected %d, got %d", len(proof.Directions), len(deserializedProof.Directions))
	}

	for i, direction := range deserializedProof.Directions {
		if direction != proof.Directions[i] {
			t.Errorf("Direction %d mismatch: expected %v, got %v", i, proof.Directions[i], direction)
		}
	}

	// Verify deserialized proof still works
	if !VerifyProof(&deserializedProof) {
		t.Error("Deserialized proof verification failed")
	}
}

func TestProofJSONHexFormat(t *testing.T) {
	// Create a tree with known data
	data := [][]byte{
		[]byte("test1"),
		[]byte("test2"),
	}

	tree, err := NewTree(data)
	if err != nil {
		t.Fatalf("Failed to create tree: %v", err)
	}

	// Generate proof
	proof, err := tree.GenerateProof(0)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("Failed to marshal proof to JSON: %v", err)
	}

	// Parse JSON to verify hex format
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &jsonMap); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Verify leaf_hash is hex string (not base64)
	leafHash, ok := jsonMap["leaf_hash"].(string)
	if !ok {
		t.Fatal("leaf_hash is not a string")
	}

	if _, err := hex.DecodeString(leafHash); err != nil {
		t.Errorf("leaf_hash is not valid hex: %v", err)
	}

	// Verify root_hash is hex string (not base64)
	rootHash, ok := jsonMap["root_hash"].(string)
	if !ok {
		t.Fatal("root_hash is not a string")
	}

	if _, err := hex.DecodeString(rootHash); err != nil {
		t.Errorf("root_hash is not valid hex: %v", err)
	}

	// Verify siblings are hex strings (not base64)
	siblingsInterface, ok := jsonMap["siblings"].([]interface{})
	if !ok {
		t.Fatal("siblings is not an array")
	}

	for i, siblingInterface := range siblingsInterface {
		sibling, ok := siblingInterface.(string)
		if !ok {
			t.Fatalf("sibling %d is not a string", i)
		}

		if _, err := hex.DecodeString(sibling); err != nil {
			t.Errorf("sibling %d is not valid hex: %v", i, err)
		}
	}

	// Verify the JSON format doesn't contain base64 indicators
	jsonString := string(jsonData)
	if len(leafHash) == 44 && leafHash[len(leafHash)-1] == '=' {
		t.Error("leaf_hash appears to be base64 encoded (ends with =)")
	}

	if len(rootHash) == 44 && rootHash[len(rootHash)-1] == '=' {
		t.Error("root_hash appears to be base64 encoded (ends with =)")
	}

	// Hex strings should be exactly 64 characters for SHA256 hashes
	if len(leafHash) != 64 {
		t.Errorf("leaf_hash should be 64 characters (32 bytes hex), got %d", len(leafHash))
	}

	if len(rootHash) != 64 {
		t.Errorf("root_hash should be 64 characters (32 bytes hex), got %d", len(rootHash))
	}

	t.Logf("JSON output: %s", jsonString)
}

func TestLargeTree(t *testing.T) {
	// Test with a larger tree to ensure it works with many levels
	data := make([][]byte, 1000)
	for i := 0; i < 1000; i++ {
		data[i] = []byte(hex.EncodeToString([]byte("test_data_" + string(rune(i)))))
	}

	tree, err := NewTree(data)
	if err != nil {
		t.Fatalf("Failed to create large tree: %v", err)
	}

	// Test proof for element in the middle
	proof, err := tree.GenerateProof(500)
	if err != nil {
		t.Fatalf("Failed to generate proof for large tree: %v", err)
	}

	// Verify the proof
	if !VerifyProof(proof) {
		t.Error("Large tree proof verification failed")
	}

	// Verify number of siblings is logarithmic
	expectedSiblings := 10 // log2(1000) ≈ 10
	if len(proof.Siblings) != expectedSiblings {
		t.Errorf("Expected approximately %d siblings, got %d", expectedSiblings, len(proof.Siblings))
	}
}

func TestEdgeCases(t *testing.T) {
	// Test with single element
	singleData := [][]byte{[]byte("single")}
	tree, err := NewTree(singleData)
	if err != nil {
		t.Fatalf("Failed to create single-element tree: %v", err)
	}

	proof, err := tree.GenerateProof(0)
	if err != nil {
		t.Fatalf("Failed to generate proof for single element: %v", err)
	}

	if !VerifyProof(proof) {
		t.Error("Single element proof verification failed")
	}

	// Test with empty data (should fail)
	_, err = NewTree([][]byte{})
	if err == nil {
		t.Error("Expected error for empty data")
	}

	// Test proof for invalid index
	_, err = tree.GenerateProof(-1)
	if err == nil {
		t.Error("Expected error for negative index")
	}

	_, err = tree.GenerateProof(1)
	if err == nil {
		t.Error("Expected error for out-of-bounds index")
	}
}

func TestFindLeafIndex(t *testing.T) {
	// Create a tree with known data
	data := [][]byte{
		[]byte("test1"),
		[]byte("test2"),
		[]byte("test3"),
		[]byte("test4"),
	}

	tree, err := NewTree(data)
	if err != nil {
		t.Fatalf("Failed to create tree: %v", err)
	}

	// Test finding existing leaf
	index := tree.FindLeafIndex(tree.Leaves[2].Hash)
	if index != 2 {
		t.Errorf("Expected index 2, got %d", index)
	}

	// Test finding non-existing leaf
	nonExistentHash := []byte("nonexistent")
	index = tree.FindLeafIndex(nonExistentHash)
	if index != -1 {
		t.Errorf("Expected -1 for non-existent hash, got %d", index)
	}
}

func TestMerkleProofHexEncodingIntegration(t *testing.T) {
	// Create test data similar to real-world usage
	data := [][]byte{
		[]byte("test content for hex encoding verification"),
		[]byte("test content 1"),
		[]byte("test content 2"),
		[]byte("test content 3"),
		[]byte("test content 4"),
		[]byte("test content 5"),
	}

	tree, err := NewTree(data)
	if err != nil {
		t.Fatalf("Failed to create tree: %v", err)
	}

	// Generate proof for the first file
	proof, err := tree.GenerateProof(0)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal proof to JSON: %v", err)
	}

	t.Logf("Generated merkle proof JSON:\n%s", string(jsonData))

	// Verify the JSON structure matches expected format
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonData, &jsonMap); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Test that all hash fields are hex strings (not base64)
	testHexField := func(fieldName string, expectedLength int) {
		field, exists := jsonMap[fieldName]
		if !exists {
			t.Errorf("Field %s not found in JSON", fieldName)
			return
		}

		hashStr, ok := field.(string)
		if !ok {
			t.Errorf("Field %s is not a string", fieldName)
			return
		}

		// Verify it's valid hex
		if _, err := hex.DecodeString(hashStr); err != nil {
			t.Errorf("Field %s is not valid hex: %v", fieldName, err)
		}

		// Verify length (SHA256 = 64 hex characters)
		if len(hashStr) != expectedLength {
			t.Errorf("Field %s should be %d characters, got %d", fieldName, expectedLength, len(hashStr))
		}

		// Verify it's not base64 (base64 for 32 bytes would be 44 chars ending with =)
		if len(hashStr) == 44 && hashStr[len(hashStr)-1] == '=' {
			t.Errorf("Field %s appears to be base64 encoded instead of hex", fieldName)
		}
	}

	testHexField("leaf_hash", 64)
	testHexField("root_hash", 64)

	// Test siblings array
	siblings, ok := jsonMap["siblings"].([]interface{})
	if !ok {
		t.Fatal("siblings field is not an array")
	}

	if len(siblings) == 0 {
		t.Fatal("siblings array is empty")
	}

	for i, siblingInterface := range siblings {
		sibling, ok := siblingInterface.(string)
		if !ok {
			t.Errorf("sibling %d is not a string", i)
			continue
		}

		if _, err := hex.DecodeString(sibling); err != nil {
			t.Errorf("sibling %d is not valid hex: %v", i, err)
		}

		if len(sibling) != 64 {
			t.Errorf("sibling %d should be 64 characters, got %d", i, len(sibling))
		}

		// Verify it's not base64
		if len(sibling) == 44 && sibling[len(sibling)-1] == '=' {
			t.Errorf("sibling %d appears to be base64 encoded instead of hex", i)
		}
	}

	// Test that the proof can be verified
	if !VerifyProof(proof) {
		t.Error("Generated proof verification failed")
	}

	// Test consistency across multiple proofs
	for i := 0; i < len(data); i++ {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			t.Errorf("Failed to generate proof for index %d: %v", i, err)
			continue
		}

		if !VerifyProof(proof) {
			t.Errorf("Proof verification failed for index %d", i)
		}

		// Verify root hash is consistent
		if proof.RootHash != hex.EncodeToString(tree.GetRootHash()) {
			t.Errorf("Root hash mismatch for index %d", i)
		}
	}
}

func TestMerkleProofBackwardCompatibility(t *testing.T) {
	// Test that proofs generated with hex encoding can be deserialized
	// This simulates a client receiving a JSON response from the server
	
	// Create a sample proof
	data := [][]byte{
		[]byte("test1"),
		[]byte("test2"),
	}

	tree, err := NewTree(data)
	if err != nil {
		t.Fatalf("Failed to create tree: %v", err)
	}

	originalProof, err := tree.GenerateProof(0)
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Serialize to JSON (simulating server response)
	jsonData, err := json.Marshal(originalProof)
	if err != nil {
		t.Fatalf("Failed to marshal proof: %v", err)
	}

	// Deserialize from JSON (simulating client parsing)
	var receivedProof Proof
	if err := json.Unmarshal(jsonData, &receivedProof); err != nil {
		t.Fatalf("Failed to unmarshal proof: %v", err)
	}

	// Verify the deserialized proof works
	if !VerifyProof(&receivedProof) {
		t.Error("Deserialized proof verification failed")
	}

	// Verify all fields match
	if receivedProof.LeafHash != originalProof.LeafHash {
		t.Error("LeafHash mismatch after serialization")
	}

	if receivedProof.RootHash != originalProof.RootHash {
		t.Error("RootHash mismatch after serialization")
	}

	if receivedProof.LeafIndex != originalProof.LeafIndex {
		t.Error("LeafIndex mismatch after serialization")
	}

	if len(receivedProof.Siblings) != len(originalProof.Siblings) {
		t.Error("Siblings length mismatch after serialization")
	}

	for i, sibling := range receivedProof.Siblings {
		if sibling != originalProof.Siblings[i] {
			t.Errorf("Sibling %d mismatch after serialization", i)
		}
	}
}

// Test GetLeafCount function - currently 0% coverage
func TestGetLeafCount(t *testing.T) {
	// Test with various tree sizes
	testCases := []struct {
		name     string
		dataSize int
	}{
		{"single leaf", 1},
		{"two leaves", 2},
		{"three leaves", 3},
		{"four leaves", 4},
		{"large tree", 100},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := make([][]byte, tc.dataSize)
			for i := 0; i < tc.dataSize; i++ {
				data[i] = []byte("test_data_" + string(rune(i)))
			}

			tree, err := NewTree(data)
			if err != nil {
				t.Fatalf("Failed to create tree: %v", err)
			}

			leafCount := tree.GetLeafCount()
			if leafCount != tc.dataSize {
				t.Errorf("Expected leaf count %d, got %d", tc.dataSize, leafCount)
			}

			// Verify it matches the actual leaves slice length
			if leafCount != len(tree.Leaves) {
				t.Errorf("GetLeafCount() returned %d but tree.Leaves has length %d", leafCount, len(tree.Leaves))
			}
		})
	}
}

// Test GetRootHash with nil tree case - currently 66.7% coverage
func TestGetRootHash_NilRoot(t *testing.T) {
	// Create a tree and manually set Root to nil to test the nil case
	tree := &Tree{
		Root:   nil,
		Leaves: []*Node{},
	}

	rootHash := tree.GetRootHash()
	if rootHash != nil {
		t.Errorf("Expected nil root hash for nil root, got %v", rootHash)
	}
}

// Test hashPair edge cases - currently 87.5% coverage  
func TestHashPair_EdgeCases(t *testing.T) {
	// Test with same-length hashes (normal case)
	hash1 := sha256.Sum256([]byte("test1"))
	hash2 := sha256.Sum256([]byte("test2"))
	
	result1 := hashPair(hash1[:], hash2[:])
	result2 := hashPair(hash2[:], hash1[:])
	
	// Results should be the same due to deterministic ordering
	if hex.EncodeToString(result1) != hex.EncodeToString(result2) {
		t.Error("hashPair should produce same result regardless of input order for same-length hashes")
	}

	// Test with different-length hashes (edge case)
	shortHash := []byte("short")
	longHash := hash1[:]
	
	result3 := hashPair(shortHash, longHash)
	result4 := hashPair(longHash, shortHash)
	
	// These should be different since lexicographic ordering doesn't apply
	if hex.EncodeToString(result3) == hex.EncodeToString(result4) {
		t.Error("hashPair with different lengths should not produce same result when order is swapped")
	}
	
	// Verify the results are valid SHA256 hashes
	if len(result1) != 32 {
		t.Errorf("Expected 32-byte hash, got %d bytes", len(result1))
	}
	if len(result3) != 32 {
		t.Errorf("Expected 32-byte hash, got %d bytes", len(result3))
	}

	// Test lexicographic ordering with specific hex values
	// Create hashes where hex comparison matters
	earlyHash := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	
	lateHash := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

	result5 := hashPair(earlyHash, lateHash)
	result6 := hashPair(lateHash, earlyHash)
	
	// Should be same due to lexicographic ordering
	if hex.EncodeToString(result5) != hex.EncodeToString(result6) {
		t.Error("hashPair should use lexicographic ordering for same-length inputs")
	}

	// Verify the ordering is actually happening
	earlyHex := hex.EncodeToString(earlyHash)
	lateHex := hex.EncodeToString(lateHash)
	if earlyHex >= lateHex {
		t.Error("Test setup error: earlyHash should be lexicographically before lateHash")
	}
}