#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT=8545
SCRIPT="$DIR/http-evm-rpc-info.nse"

echo "========================================="
echo "   http-evm-rpc-info NSE Test Suite      "
echo "========================================="

run_test_mode() {
    local mode=$1
    local expected_text=$2
    echo -n "[*] Testing Mode: '$mode' ... "
    
    # Start mock server in background
    python3 "$DIR/tests/mock_rpc_server.py" --port "$PORT" --mode "$mode" &
    SERVER_PID=$!
    sleep 0.4

    # Run nmap scan against mock server
    OUTPUT=$(nmap -sT -Pn --script "$SCRIPT" -p "$PORT" 127.0.0.1 2>/dev/null || true)

    # Terminate server
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true

    if echo "$OUTPUT" | grep -q "$expected_text"; then
        echo "✅ PASSED"
    else
        echo "❌ FAILED (Expected: '$expected_text')"
        echo "$OUTPUT"
        exit 1
    fi
}

# Run test cases across all tiers
run_test_mode "geth" "Geth/v1.13.14"
run_test_mode "besu" "besu/v24.1.0"
run_test_mode "stripped" "Level 2 (Inferred Visibility)"
run_test_mode "erigon_obfuscated" "Erigon"
run_test_mode "unauthorized" "Level 4 (Authenticated / JWT Restricted)"
run_test_mode "forbidden" "Level 4 (Firewalled / Access Restricted)"

echo "-----------------------------------------"
echo "🎉 All 6 Integration Test Scenarios Passed!"
echo "========================================="
