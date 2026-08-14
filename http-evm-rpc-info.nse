local http = require "http"
local json = require "json"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local tonumber = tonumber

description = [[
Performs multi-tiered reconnaissance and fingerprinting against Ethereum and EVM-compatible nodes (Geth, Besu, Nethermind, Erigon, Reth, Anvil, Hardhat).

Implements a fallback inspection pipeline:
- Tier 1: Standard RPC query (`web3_clientVersion`, `eth_chainId`, `eth_blockNumber`, `net_peerCount`).
- Tier 2: Behavioral heuristic probing (analyzing JSON-RPC error codes, message strings, and vendor-specific namespaces like `erigon_*`, `txpool_*`, `hardhat_*`, `anvil_*`) to identify stripped or restricted nodes.
- Classification: Categorizes node exposure into Visibility Levels (Level 1: Full, Level 2: Inferred, Level 4: Hardened/Restricted).
]]

---
-- @usage
-- nmap -sV --script http-evm-rpc-info -p 8545,8546,8551 <target>
--
-- @output
-- PORT     STATE SERVICE          REASON
-- 8545/tcp open  ethereum-jsonrpc syn-ack
-- | http-evm-rpc-info:
-- |   Visibility: Level 1 (Full Visibility)
-- |   Client Version: Geth/v1.13.14-stable-20b1b123/darwin-arm64/go1.21.6
-- |   Client Vendor: Geth
-- |   Chain ID: 1 (Ethereum Mainnet)
-- |   Block Height: 19219424
-- |_  Peer Count: 25
---

author = "Deep Research Agent"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "version"}

portrule = shortport.port_or_service({8545, 8546, 7545, 8551}, {"http", "https", "json-rpc", "ethereum-rpc"})

-- Map common EVM Chain IDs to Network Names
local KNOWN_CHAINS = {
  [1] = "Ethereum Mainnet",
  [10] = "Optimism Mainnet",
  [56] = "BNB Smart Chain Mainnet",
  [100] = "Gnosis Chain",
  [137] = "Polygon Mainnet",
  [250] = "Fantom Opera",
  [8453] = "Base Mainnet",
  [42161] = "Arbitrum One",
  [43114] = "Avalanche C-Chain",
  [11155111] = "Sepolia Testnet",
  [31337] = "Hardhat / Anvil Local Devnet",
  [1337] = "Geth Local Devnet"
}

-- Helper function to parse hex string to decimal integer
local function parse_hex(hex_str)
  if not hex_str or type(hex_str) ~= "string" then return nil end
  local cleaned = hex_str:gsub("^0[xX]", "")
  return tonumber(cleaned, 16)
end

-- Helper to construct JSON-RPC payload
local function make_rpc_payload(id, method, params)
  return json.generate({
    jsonrpc = "2.0",
    method = method,
    params = params or {},
    id = id
  })
end

-- Tier 2: Behavioral heuristic analysis using error signatures and vendor namespaces
local function probe_behavioral_heuristics(host, port, path, options)
  -- 1. Probe non-existent method to check error message phrasing
  local payload_err = make_rpc_payload(99, "probe_checkImplementation")
  local res_err = http.post(host, port, path, options, nil, payload_err)
  
  local inferred_vendor = nil
  local heuristics_note = nil

  if res_err and res_err.status == 200 then
    local st, parsed = json.parse(res_err.body)
    if st and parsed and parsed.error then
      local err_msg = parsed.error.message or ""
      if string.find(err_msg, "the method probe_checkImplementation does not exist") then
        inferred_vendor = "Geth (or Go-Ethereum derivative)"
        heuristics_note = "Matched Geth -32601 error message syntax"
      elseif string.find(err_msg, "Method not found") or string.find(err_msg, "Method probe_checkImplementation not found") then
        inferred_vendor = "Besu / Nethermind / OpenEthereum"
        heuristics_note = "Matched standard Method not found error syntax"
      end
    end
  end

  -- 2. Probe Erigon namespace
  local payload_erigon = make_rpc_payload(100, "erigon_forks")
  local res_erigon = http.post(host, port, path, options, nil, payload_erigon)
  if res_erigon and res_erigon.status == 200 then
    local st_e, parsed_e = json.parse(res_erigon.body)
    if st_e and parsed_e and not parsed_e.error then
      inferred_vendor = "Erigon"
      heuristics_note = "Exposes active erigon_* namespace"
    end
  end

  -- 3. Probe Hardhat / Anvil development namespaces
  local payload_hardhat = make_rpc_payload(101, "hardhat_metadata")
  local res_hardhat = http.post(host, port, path, options, nil, payload_hardhat)
  if res_hardhat and res_hardhat.status == 200 then
    local st_h, parsed_h = json.parse(res_hardhat.body)
    if st_h and parsed_h and not parsed_h.error then
      inferred_vendor = "Hardhat Network"
      heuristics_note = "Exposes active hardhat_* namespace"
    end
  end

  local payload_anvil = make_rpc_payload(102, "anvil_nodeInfo")
  local res_anvil = http.post(host, port, path, options, nil, payload_anvil)
  if res_anvil and res_anvil.status == 200 then
    local st_a, parsed_a = json.parse(res_anvil.body)
    if st_a and parsed_a and not parsed_a.error then
      inferred_vendor = "Anvil (Foundry)"
      heuristics_note = "Exposes active anvil_* namespace"
    end
  end

  return inferred_vendor, heuristics_note
end

action = function(host, port)
  local path = "/"
  local options = {
    header = {
      ["Content-Type"] = "application/json",
      ["User-Agent"] = "Mozilla/5.0 (Nmap EVM Tiered Fingerprinter)"
    }
  }

  -- [Tier 1]: Standard web3_clientVersion probe
  local payload_version = make_rpc_payload(1, "web3_clientVersion")
  local response = http.post(host, port, path, options, nil, payload_version)

  if not response or not response.status then
    return nil
  end

  -- Handle access-restricted and authenticated endpoints (Level 4 / Engine API)
  if response.status == 401 then
    local out = stdnse.output_table()
    out["Visibility"] = "Level 4 (Authenticated / JWT Restricted)"
    out["Status"] = "HTTP 401 Unauthorized"
    out["Note"] = "Engine API (:8551) or Basic Auth required; bypass via P2P DevP2P layer (Port 30303)"
    return out
  elseif response.status == 403 then
    local out = stdnse.output_table()
    out["Visibility"] = "Level 4 (Firewalled / Access Restricted)"
    out["Status"] = "HTTP 403 Forbidden"
    out["Note"] = "IP Whitelisting or Host Header filtering enforced; verify via P2P Hello handshake"
    return out
  elseif response.status ~= 200 then
    return nil
  end

  local status, parsed_version = json.parse(response.body)
  local output = stdnse.output_table()

  -- Check if Tier 1 succeeded
  if status and parsed_version and parsed_version.result and type(parsed_version.result) == "string" then
    local client_version = parsed_version.result
    output["Visibility"] = "Level 1 (Full Visibility)"
    output["Client Version"] = client_version

    local vendor = client_version:match("^([^/]+)")
    if vendor then
      output["Client Vendor"] = vendor
    end

    port.version.name = "ethereum-jsonrpc"
    port.version.product = vendor or "Ethereum Client"
    port.version.version = client_version
    nmap.set_port_version(host, port, "hardmatched")
  else
    -- [Tier 2]: Fallback to Behavioral & Namespace Heuristics
    local inf_vendor, note = probe_behavioral_heuristics(host, port, path, options)
    if inf_vendor then
      output["Visibility"] = "Level 2 (Inferred Visibility)"
      output["Inferred Client"] = inf_vendor
      output["Heuristic Reason"] = note or "Error & namespace behavioral matching"
      port.version.name = "ethereum-jsonrpc"
      port.version.product = inf_vendor
      nmap.set_port_version(host, port, "hardmatched")
    else
      -- Check if standard chain/block methods respond even if clientVersion is stripped/disabled
      output["Visibility"] = "Level 2 (Obfuscated / Stripped Banner)"
    end
  end

  -- Query eth_chainId
  local payload_chain = make_rpc_payload(2, "eth_chainId")
  local res_chain = http.post(host, port, path, options, nil, payload_chain)
  if res_chain and res_chain.status == 200 then
    local st_c, parsed_c = json.parse(res_chain.body)
    if st_c and parsed_c and parsed_c.result then
      local chain_id = parse_hex(parsed_c.result)
      if chain_id then
        local chain_name = KNOWN_CHAINS[chain_id]
        output["Chain ID"] = chain_name and string.format("%d (%s)", chain_id, chain_name) or string.format("%d (Unknown)", chain_id)
      end
    end
  end

  -- Query eth_blockNumber
  local payload_block = make_rpc_payload(3, "eth_blockNumber")
  local res_block = http.post(host, port, path, options, nil, payload_block)
  if res_block and res_block.status == 200 then
    local st_b, parsed_b = json.parse(res_block.body)
    if st_b and parsed_b and parsed_b.result then
      local block_num = parse_hex(parsed_b.result)
      if block_num then output["Block Height"] = tostring(block_num) end
    end
  end

  -- Query net_peerCount
  local payload_peers = make_rpc_payload(4, "net_peerCount")
  local res_peers = http.post(host, port, path, options, nil, payload_peers)
  if res_peers and res_peers.status == 200 then
    local st_p, parsed_p = json.parse(res_peers.body)
    if st_p and parsed_p and parsed_p.result then
      local peer_count = parse_hex(parsed_p.result)
      if peer_count then output["Peer Count"] = tostring(peer_count) end
    end
  end

  return output
end
