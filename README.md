# http-evm-rpc-info: Multi-Tiered EVM Node Fingerprinting for Nmap

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Nmap Compatibility](https://img.shields.io/badge/Nmap-7.90%2B-green.svg)](https://nmap.org)
[![Engine: Lua](https://img.shields.io/badge/Engine-Lua%205.3%2F5.4-blue.svg)](https://www.lua.org)
[![EVM Networks](https://img.shields.io/badge/Chains-Ethereum%20%7C%20Arbitrum%20%7C%20Optimism%20%7C%20Polygon%20%7C%20Base-purple.svg)](data/chain_ids.json)

**`http-evm-rpc-info`** is an advanced Nmap Scripting Engine (NSE) script designed for security engineers, penetration testers, and node operators to actively discover, fingerprint, and classify Ethereum and EVM-compatible nodes (Geth, Besu, Nethermind, Erigon, Reth, Anvil, Hardhat).

Unlike basic banner grabbers that fail when standard methods (`web3_clientVersion`) are stripped or filtered, `http-evm-rpc-info` employs a **multi-tiered fallback heuristic engine** to identify node implementation families and access security postures.

---

## 🔍 Features

* **Multi-Tiered Inspection Pipeline**:
  * **Tier 1 (Standard RPC)**: Probes `web3_clientVersion`, `eth_chainId`, `eth_blockNumber`, and `net_peerCount`.
  * **Tier 2 (Behavioral & Error Heuristics)**: Inspects JSON-RPC `-32601` error syntax variations (e.g. Geth's `"the method ... does not exist/is not available"` vs. Besu/Nethermind's `"Method not found"`) and probes vendor-specific namespaces (`erigon_*`, `hardhat_*`, `anvil_*`).
  * **Tier 3 (P2P Layer Handshake Spec)**: Identifies nodes behind stripped HTTP endpoints for DevP2P RLPx handshake correlation on port `30303`.
  * **Tier 4 (Hardened/Filtered)**: Diagnoses JWT-protected Engine API endpoints (HTTP 401 on port 8551) and WAF/firewall blocks (HTTP 403).
* **Visibility Level Classification**: Categorizes target exposure into standard security levels (Level 1: Full Visibility, Level 2: Inferred, Level 4: Hardened).
* **EVM Chain Metadata**: Maps chain IDs to human-readable network names across mainnets, L2s, and testnets.
* **Offline Mock Test Harness**: Includes a lightweight Python mock server to validate all detection paths without live blockchain infrastructure.

---

## 📁 Repository Structure

```
http-evm-rpc-info/
├── README.md               # Documentation and usage guide
├── LICENSE                 # MIT License
├── http-evm-rpc-info.nse   # Core Nmap Scripting Engine module
├── data/
│   └── chain_ids.json      # Mapping of EVM Chain IDs to network metadata
├── docs/
│   └── article.md          # In-depth technical breakdown and architecture walkthrough
└── tests/
    ├── mock_rpc_server.py  # Mock EVM JSON-RPC server with multi-mode simulation
    └── test_script.sh      # Automated integration test runner
```

---

## 🚀 Installation

### Option 1: Symlink into Local Nmap Directory (Recommended)
```bash
mkdir -p ~/.nmap/scripts
ln -s "$(pwd)/http-evm-rpc-info.nse" ~/.nmap/scripts/http-evm-rpc-info.nse
nmap --script-updatedb
```

### Option 2: System-wide Installation
```bash
sudo cp http-evm-rpc-info.nse /usr/local/share/nmap/scripts/
sudo nmap --script-updatedb
```

---

## 🛠️ Usage

### Scan Default EVM RPC Ports (8545, 8546, 7545, 8551)
```bash
nmap -sV --script http-evm-rpc-info -p 8545 <target-ip>
```

### Scan Custom Subnets with Port Scanning
```bash
nmap -Pn --script http-evm-rpc-info -p 8545,8546,8551 192.168.1.0/24
```

### Run with Direct Script Path
```bash
nmap -sT -Pn --script ./http-evm-rpc-info.nse -p 8545 <target-ip>
```

---

## 📊 Sample Output

### Level 1: Full Visibility (Standard Exposed Node)
```text
PORT     STATE SERVICE
8545/tcp open  ethereum-jsonrpc
| http-evm-rpc-info: 
|   Visibility: Level 1 (Full Visibility)
|   Client Version: Geth/v1.13.14-stable-20b1b123/darwin-arm64/go1.21.6
|   Client Vendor: Geth
|   Chain ID: 1 (Ethereum Mainnet)
|   Block Height: 19219376
|_  Peer Count: 25
```

### Level 2: Inferred Visibility (Stripped Banner with Heuristic Match)
```text
PORT     STATE SERVICE
8545/tcp open  ethereum-jsonrpc
| http-evm-rpc-info: 
|   Visibility: Level 2 (Inferred Visibility)
|   Inferred Client: Geth (or Go-Ethereum derivative)
|   Heuristic Reason: Matched Geth -32601 error message syntax
|   Chain ID: 137 (Polygon Mainnet)
|_  Block Height: 54102930
```

### Level 4: Hardened / Engine API Exposure
```text
PORT     STATE SERVICE
8551/tcp open  ethereum-jsonrpc
| http-evm-rpc-info: 
|   Visibility: Level 4 (Authenticated / JWT Restricted)
|   Status: HTTP 401 Unauthorized
|_  Note: Engine API (:8551) or Basic Auth required; bypass via P2P DevP2P layer (Port 30303)
```

---

## 🧪 Testing & Validation

Run the included automated integration test suite:

```bash
chmod +x tests/test_script.sh tests/mock_rpc_server.py
./tests/test_script.sh
```

The test runner spins up `mock_rpc_server.py` across 6 distinct profiles (`geth`, `besu`, `stripped`, `erigon_obfuscated`, `unauthorized`, `forbidden`) and asserts that `http-evm-rpc-info.nse` correctly fingerprints each case.

---

## 📖 Deep Dive

For an in-depth explanation of the technical architecture, JSON-RPC error divergence, DevP2P fallback mechanics, and security implications, read [`docs/article.md`](docs/article.md).

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
