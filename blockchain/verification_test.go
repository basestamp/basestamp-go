package blockchain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/basestamp/basestamp-go/types"
)

// Values from the real basestamp-go mainnet E2E stamp.
const (
	testRoot  = "81ffa7877b32cbde1681149f9b48ac2b8edeb57c3bc5f16f53aad2712c6e5aab"
	testTx    = "0x846515a571444a046b0f87c86ac2d543a3b5d0af8a084a14a6d5fc5e19f012ce"
	testBlock = 52647560
)

type fakeChain struct {
	chainID  string
	latest   uint64
	receipt  map[string]interface{}
	tx       map[string]interface{}
	logs     []interface{}
	calls    []string
	httpCode int
}

func newFakeChain() *fakeChain {
	contract := strings.ToLower(Mainnet.ContractAddress)
	signer := strings.ToLower(Mainnet.SignerAddress)
	log := map[string]interface{}{
		"address":         contract,
		"topics":          []interface{}{StampedEventTopic, "0x" + testRoot, addressTopic(signer)},
		"data":            fmt.Sprintf("0x%064x%064x", 1792084467, testBlock),
		"blockNumber":     fmt.Sprintf("0x%x", testBlock),
		"blockHash":       "0x80b82f72c6f08396f275a1d4d98289b970cb1eb92ec03fbd093769dc8cf35735",
		"transactionHash": testTx,
		"removed":         false,
	}
	return &fakeChain{
		chainID: "0x2105",
		latest:  testBlock + 4,
		receipt: map[string]interface{}{
			"transactionHash": testTx,
			"status":          "0x1",
			"to":              contract,
			"from":            signer,
			"blockNumber":     fmt.Sprintf("0x%x", testBlock),
			"blockHash":       "0x80b82f72c6f08396f275a1d4d98289b970cb1eb92ec03fbd093769dc8cf35735",
			"logs":            []interface{}{log},
		},
		tx: map[string]interface{}{
			"hash":  testTx,
			"from":  signer,
			"to":    contract,
			"input": "0x" + StampFunctionSelector + testRoot,
		},
		logs: []interface{}{log},
	}
}

func (f *fakeChain) server(t *testing.T) (*httptest.Server, ChainConfig) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.httpCode != 0 {
			w.WriteHeader(f.httpCode)
			return
		}
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.calls = append(f.calls, req.Method)
		var result interface{}
		switch req.Method {
		case "eth_chainId":
			result = f.chainID
		case "eth_getTransactionReceipt":
			if f.receipt != nil {
				result = f.receipt
			}
		case "eth_getTransactionByHash":
			if f.tx != nil {
				result = f.tx
			}
		case "eth_blockNumber":
			result = fmt.Sprintf("0x%x", f.latest)
		case "eth_getLogs":
			result = f.logs
		default:
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "error": map[string]interface{}{"code": -32601, "message": "method not found"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
	cfg := Mainnet
	cfg.RPCURL = srv.URL
	return srv, cfg
}

func TestVerifyRootOnChain_Valid(t *testing.T) {
	f := newFakeChain()
	srv, cfg := f.server(t)
	defer srv.Close()

	a, err := NewVerifierForChain(cfg).VerifyRootOnChain(context.Background(), cfg, testTx, strings.ToUpper(testRoot))
	if err != nil {
		t.Fatalf("VerifyRootOnChain: %v", err)
	}
	if a.Root != testRoot || a.BlockNumber != testBlock || a.Confirmations != 5 || a.ChainID != 8453 {
		t.Errorf("unexpected anchor: %+v", a)
	}
	if a.BlockTimestamp.Unix() != 1792084467 {
		t.Errorf("timestamp = %v", a.BlockTimestamp)
	}
	if a.Submitter != strings.ToLower(Mainnet.SignerAddress) {
		t.Errorf("submitter = %s", a.Submitter)
	}
}

func TestVerifyRootOnChain_Rejects(t *testing.T) {
	other := "1111111111111111111111111111111111111111"
	cases := []struct {
		name   string
		mutate func(f *fakeChain)
		root   string
		anchor bool // expect ErrNotAnchored (vs. another error)
	}{
		{"wrong root", func(f *fakeChain) {}, strings.Repeat("ab", 32), true},
		{"tx not found", func(f *fakeChain) { f.receipt = nil }, testRoot, true},
		{"reverted", func(f *fakeChain) { f.receipt["status"] = "0x0" }, testRoot, true},
		{"other contract", func(f *fakeChain) { f.receipt["to"] = "0x" + other }, testRoot, true},
		{"log from other contract", func(f *fakeChain) {
			f.receipt["logs"].([]interface{})[0].(map[string]interface{})["address"] = "0x" + other
		}, testRoot, true},
		{"removed log", func(f *fakeChain) {
			f.receipt["logs"].([]interface{})[0].(map[string]interface{})["removed"] = true
		}, testRoot, true},
		{"wrong event topic", func(f *fakeChain) {
			f.receipt["logs"].([]interface{})[0].(map[string]interface{})["topics"].([]interface{})[0] = "0x" + strings.Repeat("00", 32)
		}, testRoot, true},
		{"submitter not signer", func(f *fakeChain) {
			f.receipt["logs"].([]interface{})[0].(map[string]interface{})["topics"].([]interface{})[2] = addressTopic("0x" + other)
		}, testRoot, true},
		{"no logs", func(f *fakeChain) { f.receipt["logs"] = []interface{}{} }, testRoot, true},
		{"calldata root differs", func(f *fakeChain) { f.tx["input"] = "0x" + StampFunctionSelector + strings.Repeat("cd", 32) }, testRoot, true},
		{"calldata wrong selector", func(f *fakeChain) { f.tx["input"] = "0x12345678" + testRoot }, testRoot, true},
		{"tx sender not signer", func(f *fakeChain) { f.tx["from"] = "0x" + other }, testRoot, true},
		{"not enough confirmations", func(f *fakeChain) { f.latest = testBlock - 1 }, testRoot, true},
		{"wrong chain", func(f *fakeChain) { f.chainID = "0x14a34" }, testRoot, false},
		{"rpc down", func(f *fakeChain) { f.httpCode = http.StatusBadRequest }, testRoot, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeChain()
			tc.mutate(f)
			srv, cfg := f.server(t)
			defer srv.Close()
			_, err := NewVerifierForChain(cfg).VerifyRootOnChain(context.Background(), cfg, testTx, tc.root)
			if err == nil {
				t.Fatal("expected verification to fail")
			}
			if got := errors.Is(err, ErrNotAnchored); got != tc.anchor {
				t.Errorf("errors.Is(ErrNotAnchored)=%v, want %v (err=%v)", got, tc.anchor, err)
			}
		})
	}
}

func TestVerifyRootOnChain_InputValidation(t *testing.T) {
	v := NewVerifier()
	if _, err := v.VerifyRootOnChain(context.Background(), Mainnet, "0x1234", testRoot); err == nil {
		t.Error("short tx hash accepted")
	}
	if _, err := v.VerifyRootOnChain(context.Background(), Mainnet, testTx, "zz"); err == nil {
		t.Error("bad root accepted")
	}
	cfg := Mainnet
	cfg.ContractAddress = "not-an-address"
	if _, err := v.VerifyRootOnChain(context.Background(), cfg, testTx, testRoot); err == nil {
		t.Error("bad contract accepted")
	}
}

func TestFindStampedRoot(t *testing.T) {
	f := newFakeChain()
	srv, cfg := f.server(t)
	defer srv.Close()
	v := NewVerifierForChain(cfg)

	a, err := v.FindStampedRoot(context.Background(), cfg, testRoot, testBlock, testBlock)
	if err != nil {
		t.Fatalf("FindStampedRoot: %v", err)
	}
	if a.TxHash != testTx || a.BlockNumber != testBlock {
		t.Errorf("unexpected anchor %+v", a)
	}

	f.logs = []interface{}{}
	if _, err := v.FindStampedRoot(context.Background(), cfg, testRoot, testBlock, testBlock); !errors.Is(err, ErrNotAnchored) {
		t.Errorf("empty logs: err=%v, want ErrNotAnchored", err)
	}
}

func TestVerifyProof_PinnedNetwork(t *testing.T) {
	v := NewVerifierForChain(Mainnet)
	// A proof claiming Sepolia must not be checked against (or accepted for) mainnet.
	err := v.VerifyProof(&proofFixture)
	if err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Errorf("expected pinned-network error, got %v", err)
	}
}

func TestConfigForNetwork(t *testing.T) {
	for _, n := range []string{"BASE Mainnet", "BASE", "base mainnet"} {
		if c, err := ConfigForNetwork(n); err != nil || c.ChainID != 8453 {
			t.Errorf("%q -> %+v %v", n, c, err)
		}
	}
	if c, err := ConfigForNetwork("BASE Sepolia"); err != nil || c.ChainID != 84532 {
		t.Errorf("sepolia -> %+v %v", c, err)
	}
	if _, err := ConfigForNetwork("Ethereum"); err == nil {
		t.Error("unknown network accepted")
	}
	if got := Mainnet.ExplorerURL(testTx); got != "https://basescan.org/tx/"+testTx {
		t.Errorf("explorer url %s", got)
	}
}

func TestParseQuantity(t *testing.T) {
	for in, want := range map[string]uint64{"0x0": 0, "0x1": 1, "0x2105": 8453} {
		if got, err := parseQuantity(in); err != nil || got != want {
			t.Errorf("%s -> %d %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0x", "0xzz", "0x1ffffffffffffffff"} {
		if _, err := parseQuantity(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

var proofFixture = types.Proof{
	Network:    "BASE Sepolia",
	TxID:       testTx,
	MerkleRoot: testRoot,
	MerkleProof: &types.MerkleProof{
		LeafHash:   testRoot,
		Siblings:   []string{},
		Directions: []bool{},
		RootHash:   testRoot,
	},
}
