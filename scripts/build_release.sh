#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
cargo build --release
mkdir -p CLIENTE_PORTABLE
cp target/release/warden11 CLIENTE_PORTABLE/warden11
cp README.md CLIENTE_PORTABLE/README.txt
cp -r dashboard rules docs examples CLIENTE_PORTABLE/
echo "Build ready: CLIENTE_PORTABLE/warden11"
