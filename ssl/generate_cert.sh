#!/bin/bash

# One-time certificate generation script for stable certificates
# These certificates will be reused across all builds

set -e

SSL_DIR="$(dirname "$0")"
CERT_PATH="$SSL_DIR/identity.getpostman.com.crt"
KEY_PATH="$SSL_DIR/identity.getpostman.com.key"
METADATA_PATH="$SSL_DIR/metadata.json"

# Only generate if certificates don't exist
if [ -f "$CERT_PATH" ] && [ -f "$KEY_PATH" ]; then
    echo "Certificates already exist in $SSL_DIR"
    echo "To regenerate, delete existing certificates first"
    exit 0
fi

echo "Generating stable SSL certificates for identity.getpostman.com..."

# Generate private key
openssl genrsa -out "$KEY_PATH" 2048 2>/dev/null

# Create certificate signing request
openssl req -new -key "$KEY_PATH" -out "$SSL_DIR/temp.csr" \
    -subj "/C=US/O=Postdot Technologies, Inc/CN=identity.getpostman.com" 2>/dev/null

# Create extensions file for SAN
cat > "$SSL_DIR/temp.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = identity.getpostman.com
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

# Generate self-signed certificate valid for 10 years
openssl x509 -req -in "$SSL_DIR/temp.csr" -signkey "$KEY_PATH" -out "$CERT_PATH" \
    -days 3650 -sha256 -extfile "$SSL_DIR/temp.ext" 2>/dev/null

# Clean up temporary files
rm -f "$SSL_DIR/temp.csr" "$SSL_DIR/temp.ext"

# Set proper permissions
chmod 644 "$CERT_PATH"
chmod 600 "$KEY_PATH"

# Extract metadata
SHA1=$(openssl x509 -in "$CERT_PATH" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')
NOT_BEFORE=$(openssl x509 -in "$CERT_PATH" -noout -startdate | cut -d= -f2)
NOT_AFTER=$(openssl x509 -in "$CERT_PATH" -noout -enddate | cut -d= -f2)
SERIAL=$(openssl x509 -in "$CERT_PATH" -noout -serial | cut -d= -f2)

# Create metadata.json
cat > "$METADATA_PATH" <<JSON
{
  "version": "1.0",
  "generated": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "certificate": {
    "path": "identity.getpostman.com.crt",
    "sha1": "$SHA1",
    "notBefore": "$NOT_BEFORE",
    "notAfter": "$NOT_AFTER",
    "serial": "$SERIAL",
    "subject": "/C=US/O=Postdot Technologies, Inc/CN=identity.getpostman.com"
  },
  "privateKey": {
    "path": "identity.getpostman.com.key",
    "algorithm": "RSA",
    "bits": 2048
  }
}
JSON

echo "Successfully generated stable certificates:"
echo "  Certificate: $CERT_PATH"
echo "  Private Key: $KEY_PATH"
echo "  Metadata:    $METADATA_PATH"
echo ""
echo "Certificate SHA1: $SHA1"
echo "Valid until: $NOT_AFTER"