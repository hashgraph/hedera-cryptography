#!/bin/bash

# Set the current directory
CURRENT_DIR=$(pwd)

# Define paths for different targets
TARGET_DIR="$CURRENT_DIR/target"
DARWIN_ARM64_SRC="$TARGET_DIR/aarch64-apple-darwin/release/libbn254.dylib"
LINUX_ARM64_SRC="$TARGET_DIR/aarch64-unknown-linux-gnu/release/libbn254.so"
DARWIN_AMD64_SRC="$TARGET_DIR/x86_64-apple-darwin/release/libbn254.dylib"
LINUX_AMD64_SRC="$TARGET_DIR/x86_64-unknown-linux-gnu/release/libbn254.so"

# Define destination paths
DARWIN_ARM64_DEST="$CURRENT_DIR/src/main/resources/software/darwin/arm64/libbn254.dylib"
LINUX_ARM64_DEST="$CURRENT_DIR/src/main/resources/software/linux/arm64/libbn254.so"
DARWIN_AMD64_DEST="$CURRENT_DIR/src/main/resources/software/darwin/amd64/libbn254.dylib"
LINUX_AMD64_DEST="$CURRENT_DIR/src/main/resources/software/linux/amd64/libbn254.so"

# Remove the target directory if it exists
if [ -d "$TARGET_DIR" ]; then
    echo "Removing existing target directory..."
    rm -rf "$TARGET_DIR"
fi

# Run cargo zigbuild with specified targets
echo "Running cargo zigbuild..."
cargo zigbuild --target aarch64-unknown-linux-gnu --target x86_64-apple-darwin --target aarch64-apple-darwin --target aarch64-unknown-linux-gnu --target x86_64-unknown-linux-gnu --release

# Check and copy each file to its destination
echo "Copying built files to the appropriate directories..."

if [ -f "$DARWIN_ARM64_SRC" ]; then
    mkdir -p "$(dirname "$DARWIN_ARM64_DEST")"
    cp "$DARWIN_ARM64_SRC" "$DARWIN_ARM64_DEST"
    echo "Copied $DARWIN_ARM64_SRC to $DARWIN_ARM64_DEST"
else
    echo "File $DARWIN_ARM64_SRC not found!"
fi

if [ -f "$LINUX_ARM64_SRC" ]; then
    mkdir -p "$(dirname "$LINUX_ARM64_DEST")"
    cp "$LINUX_ARM64_SRC" "$LINUX_ARM64_DEST"
    echo "Copied $LINUX_ARM64_SRC to $LINUX_ARM64_DEST"
else
    echo "File $LINUX_ARM64_SRC not found!"
fi

if [ -f "$DARWIN_AMD64_SRC" ]; then
    mkdir -p "$(dirname "$DARWIN_AMD64_DEST")"
    cp "$DARWIN_AMD64_SRC" "$DARWIN_AMD64_DEST"
    echo "Copied $DARWIN_AMD64_SRC to $DARWIN_AMD64_DEST"
else
    echo "File $DARWIN_AMD64_SRC not found!"
fi

if [ -f "$LINUX_AMD64_SRC" ]; then
    mkdir -p "$(dirname "$LINUX_AMD64_DEST")"
    cp "$LINUX_AMD64_SRC" "$LINUX_AMD64_DEST"
    echo "Copied $LINUX_AMD64_SRC to $LINUX_AMD64_DEST"
else
    echo "File $LINUX_AMD64_SRC not found!"
fi

echo "Done!"
