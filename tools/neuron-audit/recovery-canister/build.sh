#!/usr/bin/env bash
# Builds the recovery canister Wasm and prints its SHA-256. Run from anywhere.
set -euo pipefail
cd "$(dirname "$0")"
# Strip absolute paths so the output does not depend on the checkout location.
export RUSTFLAGS="--remap-path-prefix=$PWD=/recovery-canister --remap-path-prefix=$HOME/.cargo=/cargo"
cargo build --locked --release --target wasm32-unknown-unknown
out=target/wasm32-unknown-unknown/release/recovery_canister.wasm
shasum -a 256 "$out"
wc -c "$out"
