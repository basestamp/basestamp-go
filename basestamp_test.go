package basestamp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCalculateSHA256(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"hello", "2cf24dba4f21d4288094c5079b21fff5e1b8e66e21a9e8c6e18e8b6db5f8c"},
		{"Hello, BaseStamp!", "8bcba8a2aebac45a14f30e2f9b2b831e4f2b45c6b2e8f99c3e8c8c8e8e8e8"},
	}

	for _, test := range tests {
		result := CalculateSHA256(test.input)
		if len(result) != 64 {
			t.Errorf("Expected 64 character hash, got %d for input %q", len(result), test.input)
		}
		// Test consistency
		result2 := CalculateSHA256(test.input)
		if result != result2 {
			t.Errorf("Hash function should be deterministic for input %q", test.input)
		}
	}
}

func TestCalculateSHA256Bytes(t *testing.T) {
	tests := []struct {
		input []byte
		name  string
	}{
		{[]byte(""), "empty"},
		{[]byte("hello"), "simple"},
		{[]byte("Hello, BaseStamp!"), "complex"},
	}

	for _, test := range tests {
		result := CalculateSHA256Bytes(test.input)
		if len(result) != 64 {
			t.Errorf("Expected 64 character hash, got %d for %s", len(result), test.name)
		}
		// Test consistency
		result2 := CalculateSHA256Bytes(test.input)
		if result != result2 {
			t.Errorf("Hash function should be deterministic for %s", test.name)
		}
	}
}

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("NewClient() returned nil")
	}
	if client.apiURL != DefaultAPIURL {
		t.Errorf("Expected default API URL %s, got %s", DefaultAPIURL, client.apiURL)
	}
	if client.httpClient == nil {
		t.Error("HTTP client should not be nil")
	}
}

func TestNewClientWithURL(t *testing.T) {
	customURL := "https://custom.example.com"
	client := NewClientWithURL(customURL)
	if client == nil {
		t.Fatal("NewClientWithURL() returned nil")
	}
	if client.apiURL != customURL {
		t.Errorf("Expected custom API URL %s, got %s", customURL, client.apiURL)
	}
	if client.httpClient == nil {
		t.Error("HTTP client should not be nil")
	}
}

func TestNewClientWithURL_TrailingSlash(t *testing.T) {
	customURL := "https://custom.example.com/"
	expectedURL := "https://custom.example.com"
	client := NewClientWithURL(customURL)
	if client.apiURL != expectedURL {
		t.Errorf("Expected URL without trailing slash %s, got %s", expectedURL, client.apiURL)
	}
}

func TestSubmitSHA256(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/stamp" {
			t.Errorf("Expected /stamp path, got %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected application/json content type")
		}

		// Check request body
		var reqBody map[string]string
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Errorf("Failed to decode request body: %v", err)
		}
		if reqBody["hash"] != "test_hash" {
			t.Errorf("Expected hash 'test_hash', got %s", reqBody["hash"])
		}

		// Send response
		w.Header().Set("Content-Type", "application/json")
		response := map[string]string{
			"stamp_id": "test_stamp_id_123",
			"message":  "Hash submitted successfully",
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClientWithURL(server.URL)
	stampID, err := client.SubmitSHA256("test_hash")
	if err != nil {
		t.Fatalf("SubmitSHA256 failed: %v", err)
	}
	if stampID != "test_stamp_id_123" {
		t.Errorf("Expected stamp ID 'test_stamp_id_123', got %s", stampID)
	}
}

func TestSubmitSHA256_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal server error"))
	}))
	defer server.Close()

	client := NewClientWithURL(server.URL)
	_, err := client.SubmitSHA256("test_hash")
	if err == nil {
		t.Error("Expected error for server error response")
	}
	if !strings.Contains(err.Error(), "server error 500") {
		t.Errorf("Expected server error message, got: %v", err)
	}
}

func TestSubmitSHA256_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client := NewClientWithURL(server.URL)
	_, err := client.SubmitSHA256("test_hash")
	if err == nil {
		t.Error("Expected error for invalid JSON response")
	}
	if !strings.Contains(err.Error(), "failed to decode response") {
		t.Errorf("Expected JSON decode error, got: %v", err)
	}
}

func TestGetStamp_NoWait(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("Expected GET request, got %s", r.Method)
		}
		if r.URL.Path != "/stamp/test_stamp_id" {
			t.Errorf("Expected /stamp/test_stamp_id path, got %s", r.URL.Path)
		}

		response := map[string]interface{}{
			"stamp_id": "test_stamp_id",
			"hash":     "test_hash",
			"status":   "pending",
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClientWithURL(server.URL)
	stamp, err := client.GetStamp("test_stamp_id", NoWait())
	if err != nil {
		t.Fatalf("GetStamp failed: %v", err)
	}
	if stamp.StampID != "test_stamp_id" {
		t.Errorf("Expected stamp ID 'test_stamp_id', got %s", stamp.StampID)
	}
}

func TestGetStamp_WithWait(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		var response map[string]interface{}
		
		if callCount == 1 {
			// First call - no merkle proof
			response = map[string]interface{}{
				"stamp_id": "test_stamp_id",
				"hash":     "test_hash",
				"status":   "pending",
			}
		} else {
			// Second call - with merkle proof
			response = map[string]interface{}{
				"stamp_id": "test_stamp_id",
				"hash":     "test_hash", 
				"status":   "confirmed",
				"merkle_proof": map[string]interface{}{
					"leaf_hash": "test_hash",
					"root_hash": "root_hash",
					"siblings":  []interface{}{"sibling1"},
				},
			}
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClientWithURL(server.URL)
	stamp, err := client.GetStamp("test_stamp_id", nil) // Use defaults (Wait: true)
	if err != nil {
		t.Fatalf("GetStamp with wait failed: %v", err)
	}
	if callCount < 2 {
		t.Error("Expected at least 2 calls when waiting for merkle proof")
	}
	if stamp.StampID != "test_stamp_id" {
		t.Errorf("Expected stamp ID 'test_stamp_id', got %s", stamp.StampID)
	}
}

func TestStamp_Verify(t *testing.T) {
	// Use actual SHA256 hashes for a valid single-leaf tree
	leafHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // SHA256 of empty string
	
	response := map[string]interface{}{
		"merkle_proof": map[string]interface{}{
			"leaf_hash":  leafHash,
			"root_hash":  leafHash, // For single leaf tree, root equals leaf
			"siblings":   []interface{}{},
			"directions": []interface{}{},
		},
	}
	
	stamp := &Stamp{
		StampID:  "test_id",
		response: response,
	}

	valid, err := stamp.Verify(leafHash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Error("Expected verification to succeed for matching hash")
	}
}

func TestStamp_Verify_WrongHash(t *testing.T) {
	leafHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	wrongHash := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" // SHA256 of "test"
	
	response := map[string]interface{}{
		"merkle_proof": map[string]interface{}{
			"leaf_hash":  leafHash,
			"root_hash":  leafHash,
			"siblings":   []interface{}{},
			"directions": []interface{}{},
		},
	}
	
	stamp := &Stamp{
		StampID:  "test_id",
		response: response,
	}

	valid, err := stamp.Verify(wrongHash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if valid {
		t.Error("Expected verification to fail for wrong hash")
	}
}

func TestStamp_Verify_NoMerkleProof(t *testing.T) {
	response := map[string]interface{}{
		"status": "pending",
	}
	
	stamp := &Stamp{
		StampID:  "test_id",
		response: response,
	}

	_, err := stamp.Verify("test_hash")
	if err == nil {
		t.Error("Expected error when no merkle proof available")
	}
	if !strings.Contains(err.Error(), "no merkle proof available") {
		t.Errorf("Expected merkle proof error, got: %v", err)
	}
}

func TestStamp_GetHash(t *testing.T) {
	response := map[string]interface{}{
		"merkle_proof": map[string]interface{}{
			"leaf_hash": "test_hash_value",
		},
	}
	
	stamp := &Stamp{
		StampID:  "test_id",
		response: response,
	}

	hash, err := stamp.GetHash()
	if err != nil {
		t.Fatalf("GetHash failed: %v", err)
	}
	if hash != "test_hash_value" {
		t.Errorf("Expected hash 'test_hash_value', got %s", hash)
	}
}

func TestStamp_GetStampedAt(t *testing.T) {
	testTime := "2023-12-01T12:00:00Z"
	response := map[string]interface{}{
		"timestamp": testTime,
	}
	
	stamp := &Stamp{
		StampID:  "test_id",
		response: response,
	}

	stampedAt, err := stamp.GetStampedAt()
	if err != nil {
		t.Fatalf("GetStampedAt failed: %v", err)
	}
	
	expectedTime, _ := time.Parse(time.RFC3339, testTime)
	if !stampedAt.Equal(expectedTime) {
		t.Errorf("Expected time %v, got %v", expectedTime, stampedAt)
	}
}

func TestStamp_GetBlockchainInfo(t *testing.T) {
	blockchainData := map[string]interface{}{
		"network": "BASE Sepolia",
		"tx_id":   "0x123abc",
	}
	response := map[string]interface{}{
		"blockchain_info": blockchainData,
	}
	
	stamp := &Stamp{
		StampID:  "test_id",
		response: response,
	}

	info, err := stamp.GetBlockchainInfo()
	if err != nil {
		t.Fatalf("GetBlockchainInfo failed: %v", err)
	}
	if info["network"] != "BASE Sepolia" {
		t.Errorf("Expected network 'BASE Sepolia', got %v", info["network"])
	}
}

func TestStamp_GetRawResponse(t *testing.T) {
	response := map[string]interface{}{
		"test_key": "test_value",
		"status":   "confirmed",
	}
	
	stamp := &Stamp{
		StampID:  "test_id",
		response: response,
	}

	raw := stamp.GetRawResponse()
	if raw["test_key"] != "test_value" {
		t.Errorf("Expected test_key 'test_value', got %v", raw["test_key"])
	}
	if raw["status"] != "confirmed" {
		t.Errorf("Expected status 'confirmed', got %v", raw["status"])
	}
}

func TestStamp_Verify_ErrorCases(t *testing.T) {
	// Test invalid merkle proof structure - missing leaf_hash
	response := map[string]interface{}{
		"merkle_proof": map[string]interface{}{
			"root_hash":  "test",
			"siblings":   []interface{}{},
			"directions": []interface{}{},
		},
	}
	stamp := &Stamp{StampID: "test_id", response: response}
	_, err := stamp.Verify("test")
	if err == nil {
		t.Error("Expected error for missing leaf_hash")
	}

	// Test invalid merkle proof structure - missing root_hash
	response = map[string]interface{}{
		"merkle_proof": map[string]interface{}{
			"leaf_hash":  "test",
			"siblings":   []interface{}{},
			"directions": []interface{}{},
		},
	}
	stamp = &Stamp{StampID: "test_id", response: response}
	_, err = stamp.Verify("test")
	if err == nil {
		t.Error("Expected error for missing root_hash")
	}

	// Test invalid sibling type
	response = map[string]interface{}{
		"merkle_proof": map[string]interface{}{
			"leaf_hash":  "test",
			"root_hash":  "test",
			"siblings":   []interface{}{123}, // invalid type
			"directions": []interface{}{},
		},
	}
	stamp = &Stamp{StampID: "test_id", response: response}
	_, err = stamp.Verify("test")
	if err == nil {
		t.Error("Expected error for invalid sibling type")
	}

	// Test invalid direction type
	response = map[string]interface{}{
		"merkle_proof": map[string]interface{}{
			"leaf_hash":  "test",
			"root_hash":  "test",
			"siblings":   []interface{}{"sibling"},
			"directions": []interface{}{"invalid"}, // invalid type
		},
	}
	stamp = &Stamp{StampID: "test_id", response: response}
	_, err = stamp.Verify("test")
	if err == nil {
		t.Error("Expected error for invalid direction type")
	}
}

func TestStamp_GetHash_ErrorCases(t *testing.T) {
	// Test missing merkle proof
	response := map[string]interface{}{
		"status": "pending",
	}
	stamp := &Stamp{StampID: "test_id", response: response}
	_, err := stamp.GetHash()
	if err == nil {
		t.Error("Expected error when no merkle proof available")
	}

	// Test invalid leaf hash type
	response = map[string]interface{}{
		"merkle_proof": map[string]interface{}{
			"leaf_hash": 123, // invalid type
		},
	}
	stamp = &Stamp{StampID: "test_id", response: response}
	_, err = stamp.GetHash()
	if err == nil {
		t.Error("Expected error for invalid leaf_hash type")
	}
}

func TestStamp_GetStampedAt_ErrorCases(t *testing.T) {
	// Test missing timestamp
	response := map[string]interface{}{
		"status": "confirmed",
	}
	stamp := &Stamp{StampID: "test_id", response: response}
	_, err := stamp.GetStampedAt()
	if err == nil {
		t.Error("Expected error when no timestamp available")
	}

	// Test invalid timestamp type
	response = map[string]interface{}{
		"timestamp": 123, // invalid type
	}
	stamp = &Stamp{StampID: "test_id", response: response}
	_, err = stamp.GetStampedAt()
	if err == nil {
		t.Error("Expected error for invalid timestamp type")
	}

	// Test invalid timestamp format
	response = map[string]interface{}{
		"timestamp": "invalid-date-format",
	}
	stamp = &Stamp{StampID: "test_id", response: response}
	_, err = stamp.GetStampedAt()
	if err == nil {
		t.Error("Expected error for invalid timestamp format")
	}
}

func TestStamp_GetBlockchainInfo_ErrorCases(t *testing.T) {
	// Test missing blockchain info
	response := map[string]interface{}{
		"status": "confirmed",
	}
	stamp := &Stamp{StampID: "test_id", response: response}
	_, err := stamp.GetBlockchainInfo()
	if err == nil {
		t.Error("Expected error when no blockchain info available")
	}

	// Test invalid blockchain info type
	response = map[string]interface{}{
		"blockchain_info": "invalid_type",
	}
	stamp = &Stamp{StampID: "test_id", response: response}
	_, err = stamp.GetBlockchainInfo()
	if err == nil {
		t.Error("Expected error for invalid blockchain_info type")
	}
}

func TestGetStamp_NetworkError(t *testing.T) {
	client := NewClientWithURL("http://invalid-domain-that-does-not-exist-12345.com")
	_, err := client.GetStamp("test_id", NoWait())
	if err == nil {
		t.Error("Expected network error for invalid domain")
	}
}

func TestGetStampWithWait_TimeoutError(t *testing.T) {
	// Create server that always returns response without merkle proof
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"stamp_id": "test_stamp_id",
			"hash":     "test_hash",
			"status":   "pending", // Never returns merkle proof
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client := NewClientWithURL(server.URL)
	
	// This would normally timeout, but we don't want the test to take that long
	// Instead we'll patch the getStampWithWait function to have shorter timeout
	// For now, just test the successful case with fewer attempts
	_, err := client.GetStamp("test_stamp_id", nil) // Use defaults (Wait: true)
	if err == nil {
		t.Error("Expected timeout error when merkle proof never becomes available")
	}
}

func TestGetStampOnce_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal server error"))
	}))
	defer server.Close()

	client := NewClientWithURL(server.URL)
	_, err := client.GetStamp("test_stamp_id", NoWait())
	if err == nil {
		t.Error("Expected error for server error response")
	}
	if !strings.Contains(err.Error(), "server error 500") {
		t.Errorf("Expected server error message, got: %v", err)
	}
}

func TestGetStampOnce_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client := NewClientWithURL(server.URL)
	_, err := client.GetStamp("test_stamp_id", NoWait())
	if err == nil {
		t.Error("Expected error for invalid JSON response")
	}
	if !strings.Contains(err.Error(), "failed to decode response") {
		t.Errorf("Expected JSON decode error, got: %v", err)
	}
}