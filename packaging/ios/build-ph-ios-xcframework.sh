#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PH_DIR="$ROOT_DIR/adapter/ph"
HEADER_DIR="$PH_DIR/include"
MODULE_DIR="$ROOT_DIR/packaging/ios/PhFFI"
OUTPUT_DIR="${1:-"$ROOT_DIR/target/ios-xcframework"}"
OUTPUT="$OUTPUT_DIR/Ph.xcframework"
DEVICE_TARGET="aarch64-apple-ios"
SIMULATOR_TARGET="aarch64-apple-ios-sim"

for target in "$DEVICE_TARGET" "$SIMULATOR_TARGET"; do
    if ! rustup target list --installed | grep -Fqx "$target"; then
        printf 'Missing Rust target %s. Install it with: rustup target add %s\n' "$target" "$target" >&2
        exit 1
    fi
done

if [[ -e "$OUTPUT" ]]; then
    printf 'Refusing to overwrite existing output: %s\n' "$OUTPUT" >&2
    exit 1
fi

cargo build \
    --manifest-path "$ROOT_DIR/Cargo.toml" \
    --package ph \
    --lib \
    --release \
    --target "$DEVICE_TARGET" \
    --locked \
    --offline
cargo build \
    --manifest-path "$ROOT_DIR/Cargo.toml" \
    --package ph \
    --lib \
    --release \
    --target "$SIMULATOR_TARGET" \
    --locked \
    --offline

swiftc \
    -typecheck \
    -target arm64-apple-ios15.0 \
    -sdk "$(xcrun --sdk iphoneos --show-sdk-path)" \
    -I "$MODULE_DIR" \
    "$ROOT_DIR/packaging/ios/ZprPacketFlowBridge.swift"
swiftc \
    -typecheck \
    -target arm64-apple-ios15.0-simulator \
    -sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)" \
    -I "$MODULE_DIR" \
    "$ROOT_DIR/packaging/ios/ZprPacketFlowBridge.swift"

mkdir -p "$OUTPUT_DIR"
xcodebuild -create-xcframework \
    -library "$ROOT_DIR/target/$DEVICE_TARGET/release/libph.a" \
    -headers "$HEADER_DIR" \
    -library "$ROOT_DIR/target/$SIMULATOR_TARGET/release/libph.a" \
    -headers "$HEADER_DIR" \
    -output "$OUTPUT"

printf 'Created %s\n' "$OUTPUT"
