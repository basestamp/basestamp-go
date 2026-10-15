# Changelog

## v0.3.0

### Security / correctness
- `Stamp.Verify` now performs the full check and fails closed: the hash must match the stamp,
  `leaf_hash` must equal `SHA256(utf8(nonce + hash))` (server batch nonce), the merkle path must
  reconstruct `root_hash` (== `merkle_root`), and the root must be anchored on-chain. Previously real
  (nonce-based) stamps always returned `false`, and a proof without `tx_id` returned `true` without
  checking the merkle path at all.
- On-chain verification rewritten (`blockchain.VerifyRootOnChain`): checks `eth_chainId`, receipt
  status, `to == contract`, the `Stamped(bytes32,uint256,uint256,address)` event (root + signer
  topics), `stamp(bytes32)` calldata, `tx.from == signer` and confirmations. Previously any transaction
  to any address with a matching 4-byte selector was accepted, and the chain was chosen from the
  server-supplied network name. The verification chain is now pinned by the client
  (`NewClient` -> Base mainnet; `NewClientWithURL(SepoliaAPIURL)` -> Sepolia; `WithChain` to override).
- Merkle verification validates all hashes (32-byte hex), requires `len(siblings) == len(directions)`,
  bounds proof depth, and no longer aliases input slices.
- `SubmitSHA256` validates and lowercases the hash and JSON-encodes the request body (it was built with
  string formatting); stamp IDs are URL-path-escaped; API/RPC response sizes are capped.
- The library no longer prints to stdout during verification.

### Added
- `Stamp.VerifyDetailed`, `Stamp.VerifyOffline`, `VerifyProof`, `VerifyMerkleProof`, `ProofFromResponse`,
  `NewStampFromResponse`, `VerifyFileStampProof`, `NormalizeHash`, `SubmitSHA256Context`,
  `Client.WithChain`, `Client.WithRPCHTTPClient`, `Client.Chain`, `Stamp.GetNonce/GetTxID/GetMerkleRoot/GetStatus`.
- `merkle.ComputeLeafHash`, `merkle.ComputeRoot`, `merkle.NormalizeHash`, `merkle.MaxProofDepth`.
- `blockchain.ChainConfig`, `blockchain.Mainnet`, `blockchain.Sepolia`, `blockchain.FindStampedRoot`
  (eth_getLogs), `blockchain.ErrNotAnchored`, `MainnetSignerAddress`.
- Shared cross-SDK test vectors (`testdata/vectors.json`) incl. real Base mainnet proofs, and a
  mainnet E2E test gated by `BASESTAMP_E2E=1`.

### Changed
- `GetStamp` (wait mode) waits for a confirmed stamp and stops on `status: failed`.
- `Stamp.GetHash` returns the submitted hash (`hash` field) rather than `leaf_hash` when available.
- `Stamp.GetBlockchainInfo` falls back to the top-level `tx_id`/`network`/`block_hash`/`merkle_root`.
- CLI `verify` uses the library verification (it previously never compared the hash with the leaf,
  and in hash mode verified the file hash instead of the stamped hash).

## v0.2.0

### Changed (breaking default)
- Default API URL is now Base **mainnet**: `https://api-mainnet.basestamp.io` (chain 8453,
  contract `0x634494cB65B17163A4ca84378900Ff53A4Bba05C`). Previously the default
  (`https://api.basestamp.io`) served Base Sepolia.
- CLI `--server` default is now the mainnet API.

### Added
- `MainnetAPIURL`, `SepoliaAPIURL` and chain id / contract / RPC constants for both networks.
  To keep using testnet: `basestamp.NewClientWithURL(basestamp.SepoliaAPIURL)` or
  `basestamp --server https://api-sepolia.basestamp.io`.
- On-chain verification and explorer links recognize the `"BASE Mainnet"` network name
  returned by the mainnet API.
