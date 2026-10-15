package basestamp

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/basestamp/basestamp-go/blockchain"
	"github.com/basestamp/basestamp-go/merkle"
	"github.com/basestamp/basestamp-go/types"
)

var (
	// ErrHashMismatch means the hash being verified is not the hash committed
	// to by the proof (wrong hash, wrong nonce, or tampered leaf_hash).
	ErrHashMismatch = errors.New("hash does not match the stamp")
	// ErrInvalidProof means the merkle proof is malformed or does not
	// reconstruct its root.
	ErrInvalidProof = errors.New("invalid merkle proof")
)

// VerifyOptions configures VerifyProof.
type VerifyOptions struct {
	// Chain is the Basestamp deployment to verify against. The zero value
	// means blockchain.Mainnet.
	Chain blockchain.ChainConfig
	// RPCHTTPClient is used for JSON-RPC calls (default: 30s timeout client).
	RPCHTTPClient *http.Client
	// SkipOnChain checks only the leaf binding and merkle path.
	SkipOnChain bool
}

// VerificationResult describes a successful verification.
type VerificationResult struct {
	Valid      bool
	Hash       string // normalized submitted hash
	Nonce      string
	LeafHash   string
	MerkleRoot string
	TxID       string
	// Anchor is nil when SkipOnChain was set.
	Anchor *blockchain.Anchor
}

// VerifyMerkleProof checks, without network access, that proof commits to
// hash: leaf_hash == SHA256(utf8(nonce + hash)) (or leaf_hash == hash when
// nonce is empty, for legacy proofs) and the siblings reconstruct root_hash.
// nonce is the server batch nonce; if empty, proof.Nonce is used.
func VerifyMerkleProof(hash, nonce string, proof *types.MerkleProof) error {
	if proof == nil {
		return fmt.Errorf("%w: proof is nil", ErrInvalidProof)
	}
	h, err := merkle.NormalizeHash(hash)
	if err != nil {
		return err
	}
	if nonce == "" {
		nonce = proof.Nonce
	}
	leaf, err := merkle.NormalizeHash(proof.LeafHash)
	if err != nil {
		return fmt.Errorf("%w: leaf_hash: %v", ErrInvalidProof, err)
	}
	expectedLeaf := h
	if nonce != "" {
		if expectedLeaf, err = merkle.ComputeLeafHash(h, nonce); err != nil {
			return err
		}
	}
	if leaf != expectedLeaf {
		return fmt.Errorf("%w: leaf_hash %s != SHA256(nonce + hash) %s", ErrHashMismatch, leaf, expectedLeaf)
	}

	root, err := merkle.NormalizeHash(proof.RootHash)
	if err != nil {
		return fmt.Errorf("%w: root_hash: %v", ErrInvalidProof, err)
	}
	computed, err := merkle.ComputeRoot(&merkle.Proof{
		LeafHash:   proof.LeafHash,
		LeafIndex:  proof.LeafIndex,
		Siblings:   proof.Siblings,
		Directions: proof.Directions,
		RootHash:   proof.RootHash,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	if computed != root {
		return fmt.Errorf("%w: path reconstructs %s, proof claims root %s", ErrInvalidProof, computed, root)
	}
	return nil
}

// VerifyProof verifies that hash is anchored by proof: the leaf binding and
// merkle path (VerifyMerkleProof), that proof.MerkleRoot (if set) equals the
// proof's root, and - unless opts.SkipOnChain - that proof.TxID stamped the
// root on the Basestamp contract of opts.Chain. Any failure returns an error.
func VerifyProof(ctx context.Context, hash string, proof *types.Proof, opts *VerifyOptions) (*VerificationResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts == nil {
		opts = &VerifyOptions{}
	}
	if proof == nil || proof.MerkleProof == nil {
		return nil, fmt.Errorf("no merkle proof available")
	}
	mp := proof.MerkleProof
	if err := VerifyMerkleProof(hash, mp.Nonce, mp); err != nil {
		return nil, err
	}
	h, _ := merkle.NormalizeHash(hash)
	root, _ := merkle.NormalizeHash(mp.RootHash)
	leaf, _ := merkle.NormalizeHash(mp.LeafHash)
	if proof.MerkleRoot != "" {
		claimed, err := merkle.NormalizeHash(proof.MerkleRoot)
		if err != nil || claimed != root {
			return nil, fmt.Errorf("%w: merkle_root %s != proof root_hash %s", ErrInvalidProof, proof.MerkleRoot, mp.RootHash)
		}
	}
	res := &VerificationResult{
		Hash:       h,
		Nonce:      mp.Nonce,
		LeafHash:   leaf,
		MerkleRoot: root,
		TxID:       proof.TxID,
	}
	if opts.SkipOnChain {
		res.Valid = true
		return res, nil
	}

	if proof.TxID == "" {
		return nil, fmt.Errorf("stamp has no tx_id yet; cannot verify on-chain (use VerifyOffline for a merkle-only check)")
	}
	cfg := opts.Chain
	if cfg.RPCURL == "" {
		cfg = blockchain.Mainnet
	}
	if proof.Network != "" {
		if claimed, err := blockchain.ConfigForNetwork(proof.Network); err == nil && claimed.ChainID != cfg.ChainID {
			return nil, fmt.Errorf("stamp is on network %q but verification is pinned to %q (chain %d)", proof.Network, cfg.Name, cfg.ChainID)
		}
	}
	verifier := blockchain.NewVerifierForChain(cfg).WithHTTPClient(opts.RPCHTTPClient)
	anchor, err := verifier.VerifyRootOnChain(ctx, cfg, proof.TxID, root)
	if err != nil {
		return nil, err
	}
	res.Anchor = anchor
	res.Valid = true
	return res, nil
}
