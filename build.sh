#!/bin/bash
set -eEuo pipefail

echo ""
echo ""
echo "------------------"
echo "| BUILD scone_cli|"
echo "------------------"
echo ""
echo ""


echo "Executing: cargo fmt --all -- --check"
cargo fmt --all -- --check
echo ""
echo "Executing: cargo clippy --locked --all-targets --all-features -- -D warnings"
cargo clippy --locked --all-targets --all-features -- -D warnings
echo ""
echo "Executing: cargo test --locked --all-targets --all-features"
cargo test --locked --all-targets --all-features
echo ""
echo "Executing: cargo audit --deny warnings"
cargo audit --deny warnings
echo ""
echo "Executing: cargo +nightly udeps --all-targets --all-features"
cargo +nightly udeps --all-targets --all-features
echo ""
echo "Executing: cargo build --release --locked --all-targets --all-features"
cargo build --release --locked --all-targets --all-features
echo ""
echo "Executing: cargo doc --no-deps --locked (lib only)"
cargo doc --no-deps --locked --package scone_cli
echo ""
echo "Successfully built scone_cli"
