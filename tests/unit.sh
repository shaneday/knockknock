#!/bin/sh
set -eu

binary=${1:?usage: unit.sh PATH-TO-BINARY}

if "$binary" 2>build/no-activation.err; then
    echo "expected execution without socket activation to fail" >&2
    exit 1
fi

grep -q "no valid systemd socket activation data" build/no-activation.err
echo "unit checks passed"
