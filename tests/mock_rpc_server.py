#!/usr/bin/env python3
"""
Mock EVM JSON-RPC Server for Unit & Integration Testing of NSE Scripts.
Simulates different client behaviors (Geth, Besu, Erigon, Anvil, Stripped, Protected).
"""

import argparse
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver

class MockRPCHandler(BaseHTTPRequestHandler):
    mode = "geth"

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8")

        try:
            req = json.loads(post_data)
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        method = req.get("method")
        req_id = req.get("id", 1)

        # Mode: 401 Unauthorized (e.g. Engine API :8551)
        if self.mode == "unauthorized":
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Unauthorized"}).encode("utf-8"))
            return

        # Mode: 403 Forbidden (Firewalled / IP restriction)
        if self.mode == "forbidden":
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Forbidden"}).encode("utf-8"))
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        response = {"jsonrpc": "2.0", "id": req_id}

        if method == "web3_clientVersion":
            if self.mode == "geth":
                response["result"] = "Geth/v1.13.14-stable-20b1b123/darwin-arm64/go1.21.6"
            elif self.mode == "besu":
                response["result"] = "besu/v24.1.0/linux-x86_64/openjdk-java-17"
            elif self.mode == "erigon":
                response["result"] = "erigon/2.58.0/linux-amd64/go1.21.6"
            elif self.mode == "anvil":
                response["result"] = "anvil/v0.2.0/rust"
            elif self.mode in ("stripped", "erigon_obfuscated"):
                # Stripped banner
                response["error"] = {
                    "code": -32601,
                    "message": "the method web3_clientVersion does not exist/is not available"
                }

        elif method == "probe_checkImplementation":
            if self.mode in ("geth", "stripped"):
                response["error"] = {
                    "code": -32601,
                    "message": "the method probe_checkImplementation does not exist/is not available"
                }
            else:
                response["error"] = {
                    "code": -32601,
                    "message": "Method not found"
                }

        elif method == "erigon_forks":
            if self.mode in ("erigon", "erigon_obfuscated"):
                response["result"] = {"homestead": 1150000, "byzantium": 4370000}
            else:
                response["error"] = {"code": -32601, "message": "the method erigon_forks does not exist"}

        elif method == "hardhat_metadata":
            if self.mode == "hardhat":
                response["result"] = {"clientVersion": "hardhat"}
            else:
                response["error"] = {"code": -32601, "message": "Method not found"}

        elif method == "anvil_nodeInfo":
            if self.mode == "anvil":
                response["result"] = {"currentBlockNumber": "0x1"}
            else:
                response["error"] = {"code": -32601, "message": "Method not found"}

        elif method == "eth_chainId":
            response["result"] = "0x1"  # Mainnet

        elif method == "eth_blockNumber":
            response["result"] = "0x12543b0"  # Block 19219376

        elif method == "net_peerCount":
            response["result"] = "0x19"  # 25 peers

        else:
            response["error"] = {"code": -32601, "message": "Method not found"}

        self.wfile.write(json.dumps(response).encode("utf-8"))

    def log_message(self, format, *args):
        return

class QuietServer(HTTPServer):
    def handle_error(self, request, client_address):
        # Ignore client socket resets during port scanning
        pass

def run_server(port=8545, mode="geth"):
    MockRPCHandler.mode = mode
    server_address = ("127.0.0.1", port)
    httpd = QuietServer(server_address, MockRPCHandler)
    print(f"[*] Mock EVM RPC Server running on http://127.0.0.1:{port} (Mode: {mode})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mock EVM JSON-RPC Server")
    parser.add_argument("--port", type=int, default=8545, help="Port to bind (default: 8545)")
    parser.add_argument(
        "--mode",
        choices=["geth", "besu", "erigon", "anvil", "hardhat", "stripped", "erigon_obfuscated", "unauthorized", "forbidden"],
        default="geth",
        help="Simulation profile mode"
    )
    args = parser.parse_args()
    run_server(args.port, args.mode)
