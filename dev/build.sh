#!/bin/bash

# Build script for Postman AuthRouter
set -e

# Change to project root directory
cd "$(dirname "$0")/.."

echo "Building Postman AuthRouter with size optimization..."

# Clean previous builds
rm -rf dev/bin/
mkdir -p dev/bin/

# Get dependencies
echo "Getting dependencies..."
go mod download

# Build for macOS Intel
echo "Building for macOS Intel..."
GOOS=darwin GOARCH=amd64 go build -ldflags="-w -s" -o dev/bin/pm-authrouter-darwin-intel ./cmd/pm-authrouter

# Build for macOS Apple Silicon
echo "Building for macOS Apple Silicon..."
GOOS=darwin GOARCH=arm64 go build -ldflags="-w -s" -o dev/bin/pm-authrouter-darwin-arm64 ./cmd/pm-authrouter

# Build for Windows
echo "Building for Windows..."
GOOS=windows GOARCH=amd64 go build -ldflags="-w -s" -o dev/bin/pm-authrouter.exe ./cmd/pm-authrouter

# Build Windows service wrapper if needed (optional, since main binary handles it now)
# echo "Building Windows service wrapper..."
# GOOS=windows GOARCH=amd64 go build -o bin/service_wrapper.exe ./service/windows/service_wrapper.go

# Make binaries executable
chmod +x dev/bin/pm-authrouter*

echo "Build complete! Binaries are in the dev/bin/ directory"
echo ""
echo "Available binaries:"
ls -lh dev/bin/
echo ""
echo "Binary sizes are optimized with debug info and symbol stripping (-ldflags=\"-w -s\")"
echo "Expected final installer sizes after compression:"
echo "  Windows MSI: ~5-6MB"
echo "  macOS PKG:   ~4-5MB"
echo ""
echo "Configuration options:"
echo "  --team <name>     # Postman team name"
echo "  --saml-url <url>  # SAML initialization URL"
echo ""
echo "Windows service commands:"
echo "  pm-authrouter.exe -service install   # Install as Windows service"
echo "  pm-authrouter.exe -service start     # Start the service"
echo "  pm-authrouter.exe -service stop      # Stop the service"
echo "  pm-authrouter.exe -service remove    # Uninstall the service"
echo ""
echo "Run directly:"
echo "  sudo ./dev/bin/pm-authrouter-darwin-arm64 --team myteam --saml-url https://saml.url    # macOS Apple Silicon"
echo "  sudo ./dev/bin/pm-authrouter-darwin-intel --team myteam --saml-url https://saml.url    # macOS Intel"
echo "  dev/bin/pm-authrouter.exe --team myteam --saml-url https://saml.url                     # Windows (as Administrator)"