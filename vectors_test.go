package basestamp

import (
	"context"
	"errors"
	"time"

	"encoding/json"
	"github.com/basestamp/basestamp-go/blockchain"
	"os"
	"testing"

	"github.com/basestamp/basestamp-go/merkle"
	"github.com/basestamp/basestamp-go/types"
)

// testVector is the cross-SDK vector schema shared by basestamp-go, -ts and
// -python (testdata/vectors.json). A vector is valid iff the leaf binds
// hash+nonce, the path reconstructs proof.root_hash, and that equals
// expected_root.
type testVector struct {
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	Hash         string            `json:"hash"`
	Nonce        string            `json:"nonce"`
	Proof        types.MerkleProof `json:"proof"`
	ExpectedRoot string            `json:"expected_root"`
	Valid        bool              `json:"valid"`
	StampID      string            `json:"stamp_id,omitempty"`
	TxID         string            `json:"tx_id,omitempty"`
	ChainID      uint64            `json:"chain_id,omitempty"`
}

func loadVectors(t *testing.T) []testVector {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("reading vectors: %v", err)
	}
	var vectors []testVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parsing vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	return vectors
}

func TestSharedVectors(t *testing.T) {
	var real, negative int
	for _, v := range loadVectors(t) {
		v := v
		if v.TxID != "" {
			real++
		}
		if !v.Valid {
			negative++
		}
		t.Run(v.Name, func(t *testing.T) {
			// Offline verification against the proof as returned by the API.
			proof := &types.Proof{
				MerkleRoot:  v.ExpectedRoot,
				MerkleProof: &v.Proof,
			}
			proof.MerkleProof.Nonce = v.Nonce
			_, err := VerifyProof(context.Background(), v.Hash, proof, &VerifyOptions{SkipOnChain: true})
			if got := err == nil; got != v.Valid {
				t.Fatalf("VerifyProof valid=%v, want %v (err=%v)", got, v.Valid, err)
			}

			// The same result through Stamp.VerifyOffline on an API-shaped response.
			raw, _ := json.Marshal(map[string]interface{}{
				"hash":         v.Hash,
				"nonce":        v.Nonce,
				"merkle_root":  v.ExpectedRoot,
				"merkle_proof": v.Proof,
			})
			var resp map[string]interface{}
			_ = json.Unmarshal(raw, &resp)
			ok, _ := NewStampFromResponse(nil, resp).VerifyOffline(v.Hash)
			if ok != v.Valid {
				t.Fatalf("Stamp.VerifyOffline=%v, want %v", ok, v.Valid)
			}

			if v.Valid {
				leaf, err := merkle.ComputeLeafHash(v.Hash, v.Nonce)
				if err != nil || leaf != v.Proof.LeafHash {
					t.Fatalf("ComputeLeafHash=%s (%v), want %s", leaf, err, v.Proof.LeafHash)
				}
				root, err := merkle.ComputeRoot(&merkle.Proof{LeafHash: v.Proof.LeafHash, Siblings: v.Proof.Siblings, Directions: v.Proof.Directions})
				if err != nil || root != v.ExpectedRoot {
					t.Fatalf("ComputeRoot=%s (%v), want %s", root, err, v.ExpectedRoot)
				}
			}
		})
	}
	if real == 0 || negative == 0 {
		t.Errorf("vectors must include real mainnet proofs and negative cases (real=%d negative=%d)", real, negative)
	}
}

// TestOnChainVectors re-verifies the real mainnet vectors against Base mainnet
// RPC (read-only, free). Runs when BASESTAMP_ONLINE=1 or BASESTAMP_E2E=1.
func TestOnChainVectors(t *testing.T) {
	if os.Getenv("BASESTAMP_ONLINE") != "1" && os.Getenv("BASESTAMP_E2E") != "1" {
		t.Skip("set BASESTAMP_ONLINE=1 to verify real vectors against Base mainnet RPC")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	seen := map[string]bool{}
	for _, v := range loadVectors(t) {
		if !v.Valid || v.TxID == "" || seen[v.TxID] {
			continue
		}
		seen[v.TxID] = true
		v := v
		t.Run(v.Name, func(t *testing.T) {
			proof := &types.Proof{Network: "BASE Mainnet", TxID: v.TxID, MerkleRoot: v.ExpectedRoot, MerkleProof: &v.Proof}
			proof.MerkleProof.Nonce = v.Nonce
			res, err := VerifyProof(ctx, v.Hash, proof, nil)
			if err != nil {
				t.Fatalf("on-chain verification: %v", err)
			}
			t.Logf("tx %s block %d at %s, %d confirmations", v.TxID, res.Anchor.BlockNumber, res.Anchor.BlockTimestamp, res.Anchor.Confirmations)

			verifier := blockchain.NewVerifierForChain(blockchain.Mainnet)
			if _, err := verifier.VerifyRootOnChain(ctx, blockchain.Mainnet, v.TxID, flipLastHex(v.ExpectedRoot)); !errors.Is(err, blockchain.ErrNotAnchored) {
				t.Errorf("wrong root against real tx: err=%v, want ErrNotAnchored", err)
			}
			found, err := verifier.FindStampedRoot(ctx, logsChain(), v.ExpectedRoot, res.Anchor.BlockNumber, res.Anchor.BlockNumber)
			if err != nil || found.TxHash != res.Anchor.TxHash {
				t.Errorf("eth_getLogs lookup: %+v err=%v", found, err)
			}
		})
	}
}

// logsChain is Mainnet with an RPC that serves eth_getLogs (mainnet.base.org
// does not). Override with BASESTAMP_LOGS_RPC_URL.
func logsChain() blockchain.ChainConfig {
	cfg := blockchain.Mainnet
	cfg.RPCURL = "https://base-rpc.publicnode.com"
	if u := os.Getenv("BASESTAMP_LOGS_RPC_URL"); u != "" {
		cfg.RPCURL = u
	}
	return cfg
}
