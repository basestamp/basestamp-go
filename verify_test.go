package basestamp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/basestamp/basestamp-go/blockchain"
)

// realResponse is the GET /stamp/{id} response from the basestamp-go mainnet E2E run.
const realResponse = `{
  "block_hash": "0x80b82f72c6f08396f275a1d4d98289b970cb1eb92ec03fbd093769dc8cf35735",
  "hash": "f8906cf55527395dd842b4b02f0f60d77cb55b579ddd0514b213d553cd233efe",
  "merkle_proof": {
    "directions": [],
    "leaf_hash": "81ffa7877b32cbde1681149f9b48ac2b8edeb57c3bc5f16f53aad2712c6e5aab",
    "leaf_index": 0,
    "root_hash": "81ffa7877b32cbde1681149f9b48ac2b8edeb57c3bc5f16f53aad2712c6e5aab",
    "siblings": []
  },
  "merkle_root": "81ffa7877b32cbde1681149f9b48ac2b8edeb57c3bc5f16f53aad2712c6e5aab",
  "message": "Stamp confirmed on blockchain with merkle proof",
  "network": "BASE Mainnet",
  "nonce": "1792084465820778959",
  "stamp_id": "36e05662b5ef175b70f937c245185435da49dfb245f86f44a6269d81cdd5b9b3",
  "status": "confirmed",
  "timestamp": "2026-10-15T17:14:28.096402813Z",
  "tx_id": "0x846515a571444a046b0f87c86ac2d543a3b5d0af8a084a14a6d5fc5e19f012ce"
}`

const (
	realHash  = "f8906cf55527395dd842b4b02f0f60d77cb55b579ddd0514b213d553cd233efe"
	realRoot  = "81ffa7877b32cbde1681149f9b48ac2b8edeb57c3bc5f16f53aad2712c6e5aab"
	realTx    = "0x846515a571444a046b0f87c86ac2d543a3b5d0af8a084a14a6d5fc5e19f012ce"
	realBlock = 52647560
)

func realStampResponse(t *testing.T) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(realResponse), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// fakeRPC serves the on-chain data of the real E2E transaction, with the
// Stamped event carrying stampedRoot.
func fakeRPC(t *testing.T, stampedRoot string) *httptest.Server {
	t.Helper()
	contract := strings.ToLower(MainnetContractAddress)
	signer := strings.ToLower(MainnetSignerAddress)
	log := map[string]interface{}{
		"address":         contract,
		"topics":          []string{blockchain.StampedEventTopic, "0x" + stampedRoot, "0x000000000000000000000000" + signer[2:]},
		"data":            fmt.Sprintf("0x%064x%064x", 1792084467, realBlock),
		"blockNumber":     fmt.Sprintf("0x%x", realBlock),
		"transactionHash": realTx,
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		var result interface{}
		switch req.Method {
		case "eth_chainId":
			result = "0x2105"
		case "eth_blockNumber":
			result = fmt.Sprintf("0x%x", realBlock+10)
		case "eth_getTransactionReceipt":
			result = map[string]interface{}{
				"transactionHash": realTx, "status": "0x1", "to": contract, "from": signer,
				"blockNumber": fmt.Sprintf("0x%x", realBlock), "logs": []interface{}{log},
			}
		case "eth_getTransactionByHash":
			result = map[string]interface{}{"hash": realTx, "from": signer, "to": contract, "input": "0x" + blockchain.StampFunctionSelector + stampedRoot}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
}

func mainnetClientWithRPC(url string) *Client {
	cfg := blockchain.Mainnet
	cfg.RPCURL = url
	return NewClientWithURL("http://127.0.0.1:1").WithChain(cfg)
}

func TestVerify_RealProofWithMockedChain(t *testing.T) {
	rpc := fakeRPC(t, realRoot)
	defer rpc.Close()
	client := mainnetClientWithRPC(rpc.URL)

	// StampID empty -> no refresh from the (unreachable) API.
	stamp := &Stamp{client: client, response: realStampResponse(t)}
	res, err := stamp.VerifyDetailed(context.Background(), realHash)
	if err != nil || !res.Valid {
		t.Fatalf("VerifyDetailed: %v", err)
	}
	if res.Anchor.BlockNumber != realBlock || res.Anchor.Confirmations != 11 || res.MerkleRoot != realRoot {
		t.Errorf("unexpected result %+v / %+v", res, res.Anchor)
	}
	if ok, err := stamp.Verify(strings.ToUpper(realHash)); !ok || err != nil {
		t.Errorf("Verify(uppercase hash) = %v, %v", ok, err)
	}
	if ok, err := stamp.Verify(strings.Repeat("0", 64)); ok || err != nil {
		t.Errorf("Verify(other hash) = %v, %v; want false, nil", ok, err)
	}
}

func TestVerify_RootNotStampedOnChain(t *testing.T) {
	rpc := fakeRPC(t, strings.Repeat("ab", 32)) // chain stamped a different root
	defer rpc.Close()
	stamp := &Stamp{client: mainnetClientWithRPC(rpc.URL), response: realStampResponse(t)}
	ok, err := stamp.Verify(realHash)
	if ok || !errors.Is(err, blockchain.ErrNotAnchored) {
		t.Fatalf("Verify = %v, %v; want false, ErrNotAnchored", ok, err)
	}
}

func TestVerify_TamperedResponses(t *testing.T) {
	rpc := fakeRPC(t, realRoot)
	defer rpc.Close()
	client := mainnetClientWithRPC(rpc.URL)
	flip := func(h string) string {
		return h[:len(h)-1] + map[bool]string{true: "1", false: "0"}[h[len(h)-1] == '0']
	}

	cases := map[string]func(m map[string]interface{}){
		"leaf":        func(m map[string]interface{}) { mp(m)["leaf_hash"] = flip(realRoot) },
		"proof root":  func(m map[string]interface{}) { mp(m)["root_hash"] = flip(realRoot) },
		"merkle_root": func(m map[string]interface{}) { m["merkle_root"] = flip(realRoot) },
		"both roots": func(m map[string]interface{}) {
			mp(m)["root_hash"] = flip(realRoot)
			m["merkle_root"] = flip(realRoot)
		},
		"nonce":         func(m map[string]interface{}) { m["nonce"] = "1792084465820778958" },
		"extra sibling": func(m map[string]interface{}) { mp(m)["siblings"] = []interface{}{realRoot} },
		"no tx":         func(m map[string]interface{}) { delete(m, "tx_id") },
		"sepolia claim": func(m map[string]interface{}) { m["network"] = "BASE Sepolia" },
		"short sibling": func(m map[string]interface{}) {
			mp(m)["siblings"] = []interface{}{"abcd"}
			mp(m)["directions"] = []interface{}{true}
		},
		"bad leaf index": func(m map[string]interface{}) { mp(m)["leaf_index"] = -1.0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := realStampResponse(t)
			mutate(m)
			stamp := &Stamp{client: client, response: m}
			if ok, err := stamp.Verify(realHash); ok {
				t.Fatalf("tampered stamp verified (err=%v)", err)
			}
		})
	}
}

func mp(m map[string]interface{}) map[string]interface{} {
	return m["merkle_proof"].(map[string]interface{})
}

func TestVerifyMerkleProof_LeafConstruction(t *testing.T) {
	proof, err := ProofFromResponse(realStampResponse(t))
	if err != nil {
		t.Fatal(err)
	}
	if proof.MerkleProof.Nonce != "1792084465820778959" {
		t.Fatalf("nonce not taken from top-level field: %q", proof.MerkleProof.Nonce)
	}
	if err := VerifyMerkleProof(realHash, "", proof.MerkleProof); err != nil {
		t.Fatalf("VerifyMerkleProof: %v", err)
	}
	// SHA256(hash + nonce) and SHA256(hex-decoded hash || nonce) are not the server construction.
	swapped := *proof.MerkleProof
	swapped.LeafHash = CalculateSHA256(realHash + swapped.Nonce)
	swapped.RootHash = swapped.LeafHash
	if err := VerifyMerkleProof(realHash, "", &swapped); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("hash+nonce leaf accepted: %v", err)
	}
}

func TestSubmitSHA256_ValidatesAndNormalizes(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		got = body["hash"]
		_, _ = w.Write([]byte(`{"stamp_id":"abc"}`))
	}))
	defer srv.Close()
	c := NewClientWithURL(srv.URL)
	if _, err := c.SubmitSHA256("0x" + strings.ToUpper(testHash)); err != nil {
		t.Fatal(err)
	}
	if got != testHash {
		t.Errorf("submitted %q, want lowercase %q", got, testHash)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("g", 64), `"},"x":"` + strings.Repeat("a", 56)} {
		if _, err := c.SubmitSHA256(bad); err == nil {
			t.Errorf("invalid hash %q accepted", bad)
		}
	}
}

func TestSubmitSHA256_MissingStampID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"message":"ok"}`))
	}))
	defer srv.Close()
	if _, err := NewClientWithURL(srv.URL).SubmitSHA256(testHash); err == nil {
		t.Error("expected error for missing stamp_id")
	}
}

func TestGetStamp_FailedStatusStopsPolling(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"stamp_id":"x","status":"failed","message":"boom"}`))
	}))
	defer srv.Close()
	_, err := NewClientWithURL(srv.URL).GetStamp("x", &GetStampOptions{MaxAttempts: 5, RetryDelay: time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "boom") || calls != 1 {
		t.Errorf("err=%v calls=%d", err, calls)
	}
}

func TestGetStamp_EscapesStampID(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	_, _ = NewClientWithURL(srv.URL).GetStamp("../info?x=1", NoWait())
	if path != "/stamp/..%2Finfo%3Fx=1" {
		t.Errorf("path = %q", path)
	}
	if _, err := NewClientWithURL(srv.URL).GetStamp("", NoWait()); err == nil {
		t.Error("empty stamp id accepted")
	}
}

func TestClientChainPinning(t *testing.T) {
	if NewClient().Chain().ChainID != MainnetChainID {
		t.Error("default client not pinned to mainnet")
	}
	if NewClientWithURL(SepoliaAPIURL).Chain().ChainID != SepoliaChainID {
		t.Error("sepolia client not pinned to sepolia")
	}
	if NewClientWithURL("http://localhost:8080").Chain().ChainID != MainnetChainID {
		t.Error("custom URL should default to mainnet verification")
	}
}

func TestStampAccessors(t *testing.T) {
	s := NewStampFromResponse(nil, realStampResponse(t))
	if s.StampID != "36e05662b5ef175b70f937c245185435da49dfb245f86f44a6269d81cdd5b9b3" {
		t.Errorf("stamp id %s", s.StampID)
	}
	if h, _ := s.GetHash(); h != realHash {
		t.Errorf("GetHash = %s, want submitted hash", h)
	}
	if s.GetTxID() != realTx || s.GetMerkleRoot() != realRoot || s.GetStatus() != "confirmed" || s.GetNonce() == "" {
		t.Error("accessor mismatch")
	}
	info, err := s.GetBlockchainInfo()
	if err != nil || info["tx_id"] != realTx || info["network"] != "BASE Mainnet" {
		t.Errorf("GetBlockchainInfo = %v, %v", info, err)
	}
	if ts, err := s.GetStampedAt(); err != nil || ts.IsZero() {
		t.Errorf("GetStampedAt = %v, %v", ts, err)
	}
}
