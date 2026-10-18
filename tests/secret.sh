#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TEST_DIR=$(mktemp -d)
trap 'rm -rf -- "$TEST_DIR"' EXIT

"${CC:-cc}" -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wformat=2 \
    "$PROJECT_DIR/tests/secret.c" -o "$TEST_DIR/secret-test"
cd "$TEST_DIR"
ulimit -c 0
./secret-test
