#!/usr/bin/env bash

# Exit on any error
set -e

echo "Building Standalone Executable with PyInstaller..."

# Clean up previous builds
rm -rf build/ dist/

# Install PyInstaller if not present
pip install pyinstaller

# Run PyInstaller
pyinstaller --name tls-analyzer \
            --onefile \
            --clean \
            --console \
            ./src/tls_analyzer/cli.py

echo "Build complete. Artifacts are in the dist/ directory."

# Generate SHA256 hashes if on Linux/macOS
if command -v sha256sum &> /dev/null; then
    cd dist && sha256sum tls-analyzer > checksums.txt
    echo "Checksums generated: dist/checksums.txt"
elif command -v shasum &> /dev/null; then
    cd dist && shasum -a 256 tls-analyzer > checksums.txt
    echo "Checksums generated: dist/checksums.txt"
fi
