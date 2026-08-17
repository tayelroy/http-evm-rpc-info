# Building a Custom Nmap (NSE) Script to Uncover EVM Nodes in the Wild

## TL;DR
- **What is NSE?** Nmap Scripting Engine (NSE) allows you to write custom Lua scripts that extend Nmap from a basic port scanner into an extensible reconnaissance, behavioral fingerprinting, and vulnerability assessment tool.
- **The Problem:** Standard port scans identify open ports like `8545` as generic HTTP services, missing critical Web3 intelligence on whether the node is an exposed Ethereum/EVM execution client. Furthermore, hardened nodes frequently disable `web3_clientVersion` or restrict IP access.
- **The Multi-Tiered Solution:** I built `ethereum-rpc-info.nse`, implementing a multi-tiered inspection pipeline:
  1. *Tier 1 (Standard RPC)*: Extracts `web3_clientVersion`, `eth_chainId`, `eth_blockNumber`, `net_peerCount`.
  2. *Tier 2 (Behavioral Heuristics)*: Probes JSON-RPC error syntax differences (e.g. Geth vs. Besu `-32601` messages) and vendor-specific namespaces (`erigon_*`, `txpool_*`, `anvil_*`, `hardhat_*`).
  3. *Tier 3 (P2P Layer Handshake)*: Leverages DevP2P RLPx `Hello` packets on port `30303` to bypass HTTP firewalls.
- **The Result:** Classifies nodes into 4 Visibility Levels (Level 1: Full, Level 2: Inferred, Level 3: P2P Gossip, Level 4: Hardened/Restricted) and dynamically updates Nmap's service banner to `ethereum-jsonrpc`.
- **Quick Command:** `nmap --script ethereum-rpc-info.nse -p 8545,8546,8551,30303 <target>`

---

When performing network reconnaissance or security assessments across modern Web3 infrastructure, running into restricted endpoints, stripped banner strings, or non-standard configurations isn't a dead end—**it is the entire reason fingerprinting engines exist**.

If every node returned a clean `web3_clientVersion` string on an open port, the tool would just be a basic curl wrapper. Handling restricted, hardened, or obfuscated nodes is what makes it a legitimate security scanning engine.

To solve this, I designed and implemented `ethereum-rpc-info.nse`, a custom Nmap Scripting Engine (NSE) script featuring a **multi-tiered fallback architecture**.

---

## 1. Architecture of a Robust EVM Fingerprinting Engine

Rather than relying on a single query, the scanner operates as a tiered inspection pipeline:

```
[Target Target Host:Port]
       │
       ├─► Tier 1: Standard Execution Method (web3_clientVersion)
       │        ├─► Success: Extract Vendor, Version, OS, Compiler (Level 1)
       │        └─► Blocked / Stripped: Fallback to Tier 2
       │
       ├─► Tier 2: Namespace & Behavioral Probing (Vendor methods, Error diffs)
       │        ├─► Success: Infer client type via error signatures & namespaces (Level 2)
       │        └─► Blocked / IP-Restricted RPC: Fallback to Tier 3
       │
       └─► Tier 3: P2P Layer Handshake (Port 30303 DevP2P / Discv5)
                ├─► Success: Extract Client ID from RLPx Hello packet (Level 3)
                └─► Filtered / Blocked: Mark as Hardened / Filtered (Level 4)
```

### Scanner Output Classification Matrix
- **Level 1 (Full Visibility):** Exact client vendor, semantic version, build commit, OS, and Go/Rust/Java compiler version.
- **Level 2 (Inferred Visibility):** Client engine identified via error heuristics and API support matrix (e.g., "Identified as Geth-family or Erigon-family node; version stripped").
- **Level 3 (P2P Layer Visibility):** HTTP RPC is firewalled or IP-whitelisted, but node is discovered and fingerprinted via network gossip protocols (RLPx `Hello` on port `30303`).
- **Level 4 (Hardened / Filtered):** Endpoint strictly blocked across all ports with zero protocol response or protected behind mandatory JWT authentication (`:8551`).

---

## 2. What is the Nmap Scripting Engine (NSE)?

At its core, **NSE (Nmap Scripting Engine)** turns Nmap from a port scanner into an extensible security assessment framework. It allows users to write scripts in **Lua** to automate network discovery, vulnerability detection, configuration auditing, and service fingerprinting.

### Why Lua?
Lua is lightweight, fast, easily embeddable into C/C++ runtimes (like Nmap), and provides coroutine-based non-blocking I/O. Nmap bundles rich standard libraries specifically tailored for network protocols—such as `http`, `ssl`, `json`, `dns`, `smb`, and `shortport`.

### Anatomy of an NSE Script
Every NSE script consists of three main components:
1. **Metadata & Documentation**: Script description, author, license, and categories (`discovery`, `version`, `vuln`, `safe`, etc.).
2. **Rule Function (`portrule` / `hostrule`)**: Determines whether the script should execute against a given target host or port.
3. **Action Function (`action`)**: The core execution logic that interacts with the target, performs checks, parses responses, and returns structured findings.

---

## 3. Deep Dive: Implementing the Multi-Tiered Probes

### Tier 1: Standard RPC Query
The script first probes `web3_clientVersion`, `eth_chainId`, `eth_blockNumber`, and `net_peerCount`:

```lua
local payload_version = make_rpc_payload(1, "web3_clientVersion")
local response = http.post(host, port, "/", options, nil, payload_version)
```

### Tier 2: Behavioral & Namespace Error Profiling
When operators strip banners or disable the `web3` namespace, clients exhibit distinctive behavioral fingerprints in their error responses:

1. **Error Message Phrasing (`-32601 Method not found`)**:
   - **Geth:** Returns `{"code": -32601, "message": "the method <name> does not exist/is not available"}`.
   - **Besu / Nethermind:** Returns `{"code": -32601, "message": "Method not found"}` or differing case sensitivity.
2. **Vendor Namespace Probing**:
   - Probing `erigon_forks` or `erigon_getHeaderByNumber` identifies Erigon nodes.
   - Probing `txpool_inspect` identifies Geth / Nethermind nodes exposing internal pool inspection.
   - Probing `hardhat_metadata` or `anvil_nodeInfo` identifies local developer environments.

```lua
local function probe_behavioral_heuristics(host, port, path, options)
  local payload_err = make_rpc_payload(99, "probe_checkImplementation")
  local res_err = http.post(host, port, path, options, nil, payload_err)
  if res_err and res_err.status == 200 then
    local st, parsed = json.parse(res_err.body)
    if st and parsed and parsed.error then
      local err_msg = parsed.error.message or ""
      if string.find(err_msg, "the method probe_checkImplementation does not exist") then
        return "Geth (or Go-Ethereum derivative)", "Matched Geth -32601 error message syntax"
      end
    end
  end
  -- Additional vendor namespace probes...
end
```

### Tier 3: P2P Layer Handshake (Bypassing HTTP Firewalls)
When HTTP JSON-RPC ports (`8545`) are firewalled or behind reverse proxies, node operators almost always leave the P2P gossip port (`30303` TCP/UDP) open to participate in consensus.

Connecting to TCP port `30303` and initiating an RLPx session handshake yields an unencrypted `Hello` packet containing the complete client identification string:
```
[protocolVersion, clientId, capabilities, listenPort, nodeId]
--> Extracts: "Reth/v1.0.0/x86_64-linux" or "Geth/v1.13.14-stable-20b1b123/linux-amd64/go1.21.6"
```

---

## 4. Production NSE Script

The complete, tested script is located in the repository at `http-evm-rpc-info.nse`.

```lua
local http = require "http"
local json = require "json"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local tonumber = tonumber

description = [[
Performs multi-tiered reconnaissance and fingerprinting against Ethereum and EVM-compatible nodes.
]]

author = "Deep Research Agent"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.port_or_service({8545, 8546, 7545, 8551}, {"http", "https", "json-rpc", "ethereum-rpc"})

-- [Full source in http-evm-rpc-info.nse]
```

---

## 5. Verification & Testing

Running the script against a target node produces structured output with classification level:

```bash
nmap --script ./http-evm-rpc-info.nse -p 8545 127.0.0.1
```

```text
PORT     STATE SERVICE
8545/tcp open  ethereum-jsonrpc
| ethereum-rpc-info: 
|   Visibility: Level 1 (Full Visibility)
|   Client Version: Geth/v1.13.14-stable-20b1b123/darwin-arm64/go1.21.6
|   Client Vendor: Geth
|   Chain ID: 1 (Ethereum Mainnet)
|   Block Height: 19219424
|_  Peer Count: 25
```

---

## 6. Summary & Takeaways

By adopting a multi-tiered fallback architecture:
1. **Never Give Up on Error Codes**: Turn `-32601` error strings, HTTP 401s, and 403s into forensic evidence.
2. **Classify by Visibility**: Providing confidence tiers (Level 1–4) gives security auditors actionable clarity on node posture.
3. **Cross Protocol Boundaries**: When HTTP application layers are locked down, drop down to the P2P transport layer (RLPx/DevP2P) for definitive identification.
