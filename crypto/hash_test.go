package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestHashFile(t *testing.T) {
	// Create a temporary file with known content
	content := "Hello, World!"
	tmpfile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Test hashing the file
	hash, err := HashFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("HashFile failed: %v", err)
	}

	// Verify the hash is correct
	expected := sha256.Sum256([]byte(content))
	expectedHex := hex.EncodeToString(expected[:])
	
	if hash != expectedHex {
		t.Errorf("Expected hash %s, got %s", expectedHex, hash)
	}

	// Verify hash length
	if len(hash) != 64 {
		t.Errorf("Expected hash length 64, got %d", len(hash))
	}
}

func TestHashFile_NonExistentFile(t *testing.T) {
	_, err := HashFile("nonexistent_file.txt")
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to open file") {
		t.Errorf("Expected 'failed to open file' error, got: %v", err)
	}
}

func TestHashFile_EmptyFile(t *testing.T) {
	// Create empty temporary file
	tmpfile, err := os.CreateTemp("", "empty")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	hash, err := HashFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("HashFile failed on empty file: %v", err)
	}

	// Hash of empty string
	expected := sha256.Sum256([]byte(""))
	expectedHex := hex.EncodeToString(expected[:])
	
	if hash != expectedHex {
		t.Errorf("Expected hash %s for empty file, got %s", expectedHex, hash)
	}
}

func TestHashFile_ReadError(t *testing.T) {
	// Create a file and then make it unreadable by opening it in write-only mode
	tmpfile, err := os.CreateTemp("", "readonly_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	
	// Write some content and close
	content := "test content"
	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()
	
	// Try to open directory instead of file to trigger io.Copy error
	dir, err := os.MkdirTemp("", "test_dir")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	
	// This should fail when trying to read directory as file
	_, err = HashFile(dir)
	if err == nil {
		t.Error("Expected error when trying to hash directory, got nil")
	}
	// Note: We can't easily test io.Copy failure in a portable way,
	// but this tests the file opening error path
}

func TestHashBytes(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty bytes",
			input:    []byte{},
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "hello world",
			input:    []byte("Hello, World!"),
			expected: "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
		},
		{
			name:     "binary data",
			input:    []byte{0x00, 0x01, 0x02, 0xFF},
			expected: "3d1f57c984978ef98a18378c8166c1cb8ede02c03eeb6aee7e2f121dfeee3e56",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := HashBytes(tc.input)
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
			if len(result) != 64 {
				t.Errorf("Expected hash length 64, got %d", len(result))
			}
		})
	}
}

func TestHashString(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "hello world",
			input:    "Hello, World!",
			expected: "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
		},
		{
			name:     "unicode string",
			input:    "Hello, 世界! 🌍",
			expected: "4c5bbf8d24e5546714002205ec5658b5aebb19cf16a7029287daf72dfb71e901",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := HashString(tc.input)
			// Verify it produces the same result as HashBytes
			expected := HashBytes([]byte(tc.input))
			if result != expected {
				t.Errorf("HashString and HashBytes should produce same result. Got %s, expected %s", result, expected)
			}
			if len(result) != 64 {
				t.Errorf("Expected hash length 64, got %d", len(result))
			}
		})
	}
}

func TestValidateHash(t *testing.T) {
	testCases := []struct {
		name        string
		hash        string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid hash",
			hash:        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
			expectError: false,
		},
		{
			name:        "valid hash uppercase",
			hash:        "DFFD6021BB2BD5B0AF676290809EC3A53191DD81C7F70A4B28688A362182986F",
			expectError: false,
		},
		{
			name:        "too short",
			hash:        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986",
			expectError: true,
			errorMsg:    "invalid hash length",
		},
		{
			name:        "too long",
			hash:        "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f0",
			expectError: true,
			errorMsg:    "invalid hash length",
		},
		{
			name:        "invalid hex characters",
			hash:        "gffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
			expectError: true,
			errorMsg:    "invalid hex hash",
		},
		{
			name:        "empty string",
			hash:        "",
			expectError: true,
			errorMsg:    "invalid hash length",
		},
		{
			name:        "non-hex characters",
			hash:        "ghijklmnopqrstuvwxyz1234567890abcdef1234567890abcdef1234567890ab",
			expectError: true,
			errorMsg:    "invalid hex hash",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHash(tc.hash)
			if tc.expectError {
				if err == nil {
					t.Errorf("Expected error for hash %s, got nil", tc.hash)
				} else if !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tc.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for valid hash %s, got: %v", tc.hash, err)
				}
			}
		})
	}
}

func TestCreateStampedHash(t *testing.T) {
	// Create a temporary file
	content := "Test file content for timestamping"
	tmpfile, err := os.CreateTemp("", "timestamp_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Create timestamped hash
	th, err := CreateStampedHash(tmpfile.Name())
	if err != nil {
		t.Fatalf("CreateStampedHash failed: %v", err)
	}

	// Verify structure
	if th == nil {
		t.Fatal("Expected non-nil StampedHash")
	}

	// Verify FileHash is correct
	expectedFileHash, _ := HashFile(tmpfile.Name())
	if th.FileHash != expectedFileHash {
		t.Errorf("Expected FileHash %s, got %s", expectedFileHash, th.FileHash)
	}

	// Verify Nonce is 32 hex characters (16 bytes)
	if len(th.Nonce) != 32 {
		t.Errorf("Expected nonce length 32, got %d", len(th.Nonce))
	}
	// Verify nonce is valid hex (but not necessarily 64 chars like a hash)
	if _, err := hex.DecodeString(th.Nonce); err != nil {
		t.Errorf("Nonce should be valid hex: %v", err)
	}

	// Verify Hash is correct
	expectedHash := HashString(th.FileHash + th.Nonce)
	if th.Hash != expectedHash {
		t.Errorf("Expected final hash %s, got %s", expectedHash, th.Hash)
	}

	// Verify all hashes are valid
	if err := ValidateHash(th.FileHash); err != nil {
		t.Errorf("FileHash should be valid: %v", err)
	}
	if err := ValidateHash(th.Hash); err != nil {
		t.Errorf("Final Hash should be valid: %v", err)
	}
}

func TestCreateStampedHash_NonExistentFile(t *testing.T) {
	_, err := CreateStampedHash("nonexistent_file.txt")
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to hash file") {
		t.Errorf("Expected 'failed to hash file' error, got: %v", err)
	}
}

func TestCreateStampedHash_Uniqueness(t *testing.T) {
	// Create a temporary file
	content := "Same content for uniqueness test"
	tmpfile, err := os.CreateTemp("", "uniqueness_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Create two timestamped hashes of the same file
	th1, err := CreateStampedHash(tmpfile.Name())
	if err != nil {
		t.Fatalf("First CreateStampedHash failed: %v", err)
	}

	th2, err := CreateStampedHash(tmpfile.Name())
	if err != nil {
		t.Fatalf("Second CreateStampedHash failed: %v", err)
	}

	// FileHash should be the same
	if th1.FileHash != th2.FileHash {
		t.Errorf("FileHash should be same for same file: %s vs %s", th1.FileHash, th2.FileHash)
	}

	// Nonce should be different (very high probability)
	if th1.Nonce == th2.Nonce {
		t.Error("Nonce should be different between calls (extremely unlikely to be same)")
	}

	// Final Hash should be different
	if th1.Hash == th2.Hash {
		t.Error("Final Hash should be different due to different nonces")
	}
}

func TestVerifyStampedHash(t *testing.T) {
	// Create a temporary file
	content := "File content for verification test"
	tmpfile, err := os.CreateTemp("", "verify_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Create timestamped hash
	th, err := CreateStampedHash(tmpfile.Name())
	if err != nil {
		t.Fatalf("CreateStampedHash failed: %v", err)
	}

	// Verify should succeed
	err = VerifyStampedHash(tmpfile.Name(), th)
	if err != nil {
		t.Errorf("VerifyStampedHash should succeed: %v", err)
	}
}

func TestVerifyStampedHash_NonExistentFile(t *testing.T) {
	th := &StampedHash{
		FileHash: "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f",
		Nonce:    "abcd1234567890abcdef1234567890ab",
		Hash:     "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	}

	err := VerifyStampedHash("nonexistent_file.txt", th)
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}
	if !strings.Contains(err.Error(), "failed to hash file") {
		t.Errorf("Expected 'failed to hash file' error, got: %v", err)
	}
}

func TestVerifyStampedHash_WrongFileContent(t *testing.T) {
	// Create two files with different content
	content1 := "Original file content"
	tmpfile1, err := os.CreateTemp("", "original")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile1.Name())

	if _, err := tmpfile1.Write([]byte(content1)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile1.Close(); err != nil {
		t.Fatal(err)
	}

	content2 := "Modified file content"
	tmpfile2, err := os.CreateTemp("", "modified")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile2.Name())

	if _, err := tmpfile2.Write([]byte(content2)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile2.Close(); err != nil {
		t.Fatal(err)
	}

	// Create timestamped hash for first file
	th, err := CreateStampedHash(tmpfile1.Name())
	if err != nil {
		t.Fatalf("CreateStampedHash failed: %v", err)
	}

	// Try to verify against second file (should fail)
	err = VerifyStampedHash(tmpfile2.Name(), th)
	if err == nil {
		t.Error("Expected error when verifying wrong file, got nil")
	}
	if !strings.Contains(err.Error(), "file hash mismatch") {
		t.Errorf("Expected 'file hash mismatch' error, got: %v", err)
	}
}

func TestVerifyStampedHash_CorruptedHash(t *testing.T) {
	// Create a temporary file
	content := "File content for corruption test"
	tmpfile, err := os.CreateTemp("", "corrupt_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Create valid timestamped hash
	th, err := CreateStampedHash(tmpfile.Name())
	if err != nil {
		t.Fatalf("CreateStampedHash failed: %v", err)
	}

	// Corrupt the final hash
	th.Hash = "corrupted_hash_that_does_not_match_the_expected_verification_value"

	// Verification should fail
	err = VerifyStampedHash(tmpfile.Name(), th)
	if err == nil {
		t.Error("Expected error for corrupted hash, got nil")
	}
	if !strings.Contains(err.Error(), "stamped hash verification failed") {
		t.Errorf("Expected 'stamped hash verification failed' error, got: %v", err)
	}
}

func TestVerifyStampedHash_CorruptedNonce(t *testing.T) {
	// Create a temporary file
	content := "File content for nonce corruption test"
	tmpfile, err := os.CreateTemp("", "nonce_corrupt_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Create valid timestamped hash
	th, err := CreateStampedHash(tmpfile.Name())
	if err != nil {
		t.Fatalf("CreateStampedHash failed: %v", err)
	}

	// Corrupt the nonce
	th.Nonce = "corrupted_nonce_value_32_chars_"

	// Verification should fail
	err = VerifyStampedHash(tmpfile.Name(), th)
	if err == nil {
		t.Error("Expected error for corrupted nonce, got nil")
	}
	if !strings.Contains(err.Error(), "stamped hash verification failed") {
		t.Errorf("Expected 'stamped hash verification failed' error, got: %v", err)
	}
}

// Benchmark tests
func BenchmarkHashFile(b *testing.B) {
	// Create a temporary file with some content
	content := strings.Repeat("Hello, World! This is test content for benchmarking. ", 1000)
	tmpfile, err := os.CreateTemp("", "bench")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		b.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := HashFile(tmpfile.Name())
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHashBytes(b *testing.B) {
	data := []byte(strings.Repeat("Hello, World! ", 1000))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = HashBytes(data)
	}
}

func BenchmarkCreateStampedHash(b *testing.B) {
	// Create a temporary file
	content := strings.Repeat("Benchmark content for timestamped hash creation. ", 100)
	tmpfile, err := os.CreateTemp("", "bench_timestamp")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		b.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := CreateStampedHash(tmpfile.Name())
		if err != nil {
			b.Fatal(err)
		}
	}
}