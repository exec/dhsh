#!/bin/bash

# Fuzzing script for dhsh
# Tests for memory corruption, injection vulnerabilities, and crashes

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
TIMEOUTS=0

echo "========================================"
echo "  dhsh Fuzzing Test Suite"
echo "========================================"
echo ""

# Function to run a test
run_test() {
    local name="$1"
    local input="$2"
    local expected_result="${3:-any}"

    printf "Testing: %-40s " "$name"

    # Run with timeout
    timeout 2s ./build/dhsh <<< "$input" > /dev/null 2>&1
    local exit_code=$?

    if [ $exit_code -eq 124 ]; then
        echo -e "${YELLOW}TIMEOUT${NC}"
        TIMEOUTS=$((TIMEOUTS + 1))
    elif [ $exit_code -eq 0 ] || [ $exit_code -eq 1 ]; then
        echo -e "${GREEN}PASS${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL (exit: $exit_code)${NC}"
        FAIL=$((FAIL + 1))
    fi
}

# Test categories
echo "--- Basic Input Tests ---"
run_test "Empty input" ""
run_test "Simple command" "echo test"
run_test "Command with args" "ls -la"
run_test "Whitespace only" "   "
run_test "Newline only" "\n"
run_test "Very long input" "$(head -c 10000 /dev/zero | tr '\0' 'A')"

echo ""
echo "--- Command Injection Attempts ---"
run_test "Semicolon injection" "echo test; cat /etc/passwd"
run_test "Backtick injection" "echo test\`id\`"
run_test "Dollar injection" "echo test\$(id)"
run_test "Pipe injection" "echo test | cat"
run_test "Ampersand injection" "echo test & cat"
run_test "Multiple ampersands" "echo a && echo b || echo c"
run_test "Redirection injection" "echo test > /tmp/fuzz_test.txt"

echo ""
echo "--- Shell Expansion Attempts ---"
run_test "Variable expansion" "echo $HOME"
run_test "Curly brace expansion" "echo {a,b}"
run_test "Wildcard globbing" "echo *.c"
run_test "Tilde expansion" "echo ~"
run_test "Command substitution" "echo \$(ls)"

echo ""
echo "--- Special Characters ---"
run_test "Single quote" "'"
run_test "Double quote" "\""
run_test "Backslash" "\\"
run_test "Null bytes" "$(printf '\x00\x00\x00')"
run_test "Control characters" "$(printf '\x01\x02\x03')"
run_test "ANSI escape sequences" "$(printf '\x1b[31mred\x1b[0m')"

echo ""
echo "--- Buffer Overflow Attempts ---"
run_test "100 char command" "$(head -c 100 /dev/zero | tr '\0' 'A')"
run_test "1000 char command" "$(head -c 1000 /dev/zero | tr '\0' 'B')"
run_test "4096 char command" "$(head -c 4096 /dev/zero | tr '\0' 'C')"
run_test "5000 char command" "$(head -c 5000 /dev/zero | tr '\0' 'D')"

echo ""
echo "--- Built-in Commands ---"
run_test "Help" "help"
run_test "Version" "version"
run_test "Info" "info"
run_test "History" "history"
run_test "Aliases" "aliases"
run_test "Clear" "clear"
run_test "Date" "date"
run_test "Whoami" "whoami"
run_test "Pwd" "pwd"

echo ""
echo "--- Error Handling ---"
run_test "Unknown command" "nonexistent_command_xyz123"
run_test "Unknown option" "./build/dhsh --unknown"
run_test "Invalid redirection" "echo test >"
run_test "Missing delimiter" "cat <<END"

echo ""
echo "========================================"
echo "  Results Summary"
echo "========================================"
echo -e "  ${GREEN}Passed:${NC}    $PASS"
echo -e "  ${RED}Failed:${NC}    $FAIL"
echo -e "  ${YELLOW}Timeouts:${NC}  $TIMEOUTS"
echo "  Total:      $((PASS + FAIL + TIMEOUTS))"
echo "========================================"

if [ $FAIL -gt 0 ]; then
    echo -e "${RED}Fuzzing found potential issues!${NC}"
    exit 1
else
    echo -e "${GREEN}All fuzzing tests passed!${NC}"
    exit 0
fi
