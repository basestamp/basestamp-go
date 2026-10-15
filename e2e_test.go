package basestamp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/basestamp/basestamp-go/blockchain"
)

// TestE2EMainnet stamps a random hash on Base mainnet via the production API,
// waits for confirmation and verifies the proof locally and on-chain.
//
// Each run costs real ETH, so it is skipped unless BASESTAMP_E2E=1:
//
//	BASESTAMP_E2E=1 go test -run TestE2EMainnet -v -timeout 20m .
//
// Set BASESTAMP_E2E_OUT=path.json to save the final API response.
func TestE2EMainnet(t *testing.T) {
	if os.Getenv("BASESTAMP_E2E") != "1" {
		t.Skip("set BASESTAMP_E2E=1 to run the mainnet end-to-end test (stamps a hash on Base mainnet)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	hash := hex.EncodeToString(raw[:])

	client := NewClient()
	if client.Chain().ChainID != MainnetChainID {
		t.Fatalf("default client is not pinned to mainnet: %+v", client.Chain())
	}

	// Stamp exactly once; never retried. BASESTAMP_E2E_STAMP_ID and
	// BASESTAMP_E2E_HASH resume verification of an existing stamp instead.
	stampID := os.Getenv("BASESTAMP_E2E_STAMP_ID")
	if stampID != "" {
		hash = os.Getenv("BASESTAMP_E2E_HASH")
		t.Logf("resuming existing stamp (no new stamp submitted)")
	} else {
		var err error
		stampID, err = client.SubmitSHA256Context(ctx, hash)
		if err != nil {
			t.Fatalf("submit: %v", err)
		}
	}
	t.Logf("hash=%s stamp_id=%s", hash, stampID)

	// Poll (tolerating transient API errors) for up to 10 minutes.
	var stamp *Stamp
	deadline := time.Now().Add(10 * time.Minute)
	for {
		s, err := client.GetStamp(stampID, &GetStampOptions{Wait: BoolPtr(false), Context: ctx})
		switch {
		case err != nil:
			t.Logf("poll error (will retry): %v", err)
		case s.GetStatus() == "failed":
			t.Fatalf("stamp failed: %v", s.GetRawResponse())
		case s.isReady():
			stamp = s
		default:
			t.Logf("status=%s", s.GetStatus())
		}
		if stamp != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stamp %s not confirmed within 10 minutes", stampID)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(12 * time.Second):
		}
	}

	resp := stamp.GetRawResponse()
	pretty, _ := json.MarshalIndent(resp, "", "  ")
	t.Logf("confirmed response:\n%s", pretty)
	if out := os.Getenv("BASESTAMP_E2E_OUT"); out != "" {
		if err := os.WriteFile(out, pretty, 0o644); err != nil {
			t.Errorf("writing %s: %v", out, err)
		}
	}

	txID := stamp.GetTxID()
	t.Logf("TX HASH: %s", txID)
	t.Logf("explorer: %s", blockchain.Mainnet.ExplorerURL(txID))
	t.Logf("merkle root: %s", stamp.GetMerkleRoot())

	// 1. Local merkle verification.
	if ok, err := stamp.VerifyOffline(hash); err != nil || !ok {
		t.Fatalf("offline verification failed: ok=%v err=%v", ok, err)
	}

	// 2. Full verification (leaf + path + on-chain receipt/event/calldata/signer).
	res, err := stamp.VerifyDetailed(ctx, hash)
	if err != nil || !res.Valid {
		t.Fatalf("on-chain verification failed: %v", err)
	}
	t.Logf("anchor: block=%d time=%s confirmations=%d submitter=%s",
		res.Anchor.BlockNumber, res.Anchor.BlockTimestamp, res.Anchor.Confirmations, res.Anchor.Submitter)
	if ok, err := stamp.Verify(hash); err != nil || !ok {
		t.Fatalf("Verify: ok=%v err=%v", ok, err)
	}

	// 3. Independent eth_getLogs lookup of the Stamped event.
	v := blockchain.NewVerifierForChain(blockchain.Mainnet)
	found, err := v.FindStampedRoot(ctx, logsChain(), res.MerkleRoot, res.Anchor.BlockNumber, res.Anchor.BlockNumber)
	if err != nil {
		t.Errorf("eth_getLogs lookup: %v", err)
	} else if found.TxHash != res.Anchor.TxHash {
		t.Errorf("eth_getLogs found root in tx %s, proof tx %s", found.TxHash, res.Anchor.TxHash)
	}

	// 4. Negative checks against the real proof.
	var other [32]byte
	_, _ = rand.Read(other[:])
	if ok, err := stamp.Verify(hex.EncodeToString(other[:])); ok || err != nil {
		t.Errorf("verification of a different hash: ok=%v err=%v (want false, nil)", ok, err)
	}
	proof, err := ProofFromResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	tampered := *proof
	mp := *proof.MerkleProof
	mp.RootHash = flipLastHex(mp.RootHash)
	tampered.MerkleProof = &mp
	tampered.MerkleRoot = mp.RootHash
	if _, err := VerifyProof(ctx, hash, &tampered, nil); err == nil {
		t.Error("tampered root verified")
	}
	// A correct merkle path with a root that was never stamped must fail on-chain.
	if _, err := v.VerifyRootOnChain(ctx, blockchain.Mainnet, txID, flipLastHex(res.MerkleRoot)); !errors.Is(err, blockchain.ErrNotAnchored) {
		t.Errorf("unstamped root against real tx: err=%v, want ErrNotAnchored", err)
	}
}

func flipLastHex(h string) string {
	if h == "" {
		return h
	}
	last := h[len(h)-1]
	repl := byte('0')
	if last == '0' {
		repl = '1'
	}
	return h[:len(h)-1] + string(repl)
}
