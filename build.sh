#!/bin/bash

# Run this script to build the trivy binary

set -e

# Change to script directory
cd "$(dirname "$0")"

# Set binary name
BINARY="trivy"
BIN_PATH="bin/$BINARY"

# Create bin directory if it doesn't exist
mkdir -p bin

# Build binary
go build -o "$BIN_PATH" "./cmd/$BINARY"

echo "$BINARY built successfully in $BIN_PATH"