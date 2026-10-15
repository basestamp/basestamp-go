# Changelog

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
