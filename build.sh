#!/bin/bash
set -eEuo pipefail

echo ""
echo ""
echo "-------------------------"
echo "| BUILD scone_cli packages|"
echo "-------------------------"
echo ""
echo ""


echo "Executing: cargo fmt --all -- --check"
cargo fmt --all -- --check

echo ""
echo "Executing: cargo clippy --locked --workspace --all-targets --all-features -- -D warnings"
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings

echo ""
echo "Executing: cargo test --locked --workspace --all-targets --all-features"
cargo test --locked --workspace --all-targets --all-features

echo ""
echo "Executing: cargo audit --deny warnings"
cargo audit --ignore RUSTSEC-2026-0543 --deny warnings

echo ""
echo "Executing: cargo +nightly udeps --workspace --all-targets --all-features"
cargo +nightly udeps --workspace --all-targets --all-features

echo ""
echo "Executing: cargo build --release --locked --workspace --all-targets --all-features"
cargo build --release --locked --workspace --all-targets --all-features

echo ""
echo "Executing: cargo doc --no-deps --locked --workspace"
cargo doc --no-deps --locked --workspace --all-features

echo "-----------------------------------------"
echo "Successfully built all scone cli packages!"
echo "-----------------------------------------"
