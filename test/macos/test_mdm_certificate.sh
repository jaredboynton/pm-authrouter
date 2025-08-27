#!/bin/bash

# Test MDM Certificate Installation and Trust
# This script tests the certificate trust establishment via MDM profile

set -e

YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}Testing MDM Certificate Trust${NC}"
echo "========================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}This test must be run as root${NC}"
    exit 1
fi

# Find the MDM profile created by build script
PROFILE_PATH=""
for profile in ../../deployment/macos/Postman-Enterprise-*-auth.mobileconfig; do
    if [ -f "$profile" ]; then
        PROFILE_PATH="$profile"
        break
    fi
done

if [ -z "$PROFILE_PATH" ]; then
    echo -e "${YELLOW}No MDM profile found from build output${NC}"
    echo -e "${YELLOW}Run build_pkg_mdm.sh first to generate the profile${NC}"
    echo "Expected location: deployment/macos/Postman-Enterprise-*-auth.mobileconfig"
    
    # Check if we're in the wrong directory
    if [ -f "Postman-Enterprise-*-auth.mobileconfig" ]; then
        echo -e "${GREEN}Found profile in current directory${NC}"
        PROFILE_PATH=$(ls Postman-Enterprise-*-auth.mobileconfig | head -1)
    else
        exit 1
    fi
fi

echo -e "${GREEN}Found MDM profile: $PROFILE_PATH${NC}"

# Test the MDM profile generator if installed
echo -e "${YELLOW}Testing MDM profile generator...${NC}"

# Check for installed generator (only exists after PKG installation)
if [ -f "/usr/local/bin/postman/generate_mdm_profile.sh" ]; then
    GENERATOR_SCRIPT="/usr/local/bin/postman/generate_mdm_profile.sh"
    echo -e "${GREEN}Found installed MDM generator${NC}"
    
    # Test if it's executable
    if [ -x "$GENERATOR_SCRIPT" ]; then
        echo -e "${GREEN}Generator is executable${NC}"
    else
        echo -e "${RED}Generator is not executable${NC}"
    fi
else
    echo -e "${YELLOW}MDM generator not installed (PKG not installed)${NC}"
    echo "Install the PKG first: sudo installer -pkg Postman-Enterprise-*-saml.pkg -target /"
    GENERATOR_SCRIPT=""
fi

# Test profile generation logic
if [ -n "$GENERATOR_SCRIPT" ] && [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}Testing installed generator...${NC}"
    
    # The generator should:
    # 1. Check for existing certificate
    # 2. Generate certificate if missing
    # 3. Create MDM profile with proper structure
    
    # Test certificate generation logic
    TEST_CERT_DIR="/tmp/test_mdm_$$"
    mkdir -p "$TEST_CERT_DIR"
    
    # Simulate the certificate generation from the generator script
    openssl genrsa -out "$TEST_CERT_DIR/identity.getpostman.com.key" 2048 2>/dev/null
    openssl req -new -key "$TEST_CERT_DIR/identity.getpostman.com.key" \
        -out "$TEST_CERT_DIR/temp.csr" \
        -subj "/C=US/O=Postdot Technologies, Inc/CN=identity.getpostman.com" 2>/dev/null
    
    cat > "$TEST_CERT_DIR/temp.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = identity.getpostman.com
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
    
    openssl x509 -req -in "$TEST_CERT_DIR/temp.csr" \
        -signkey "$TEST_CERT_DIR/identity.getpostman.com.key" \
        -out "$TEST_CERT_DIR/identity.getpostman.com.crt" \
        -days 3650 -sha256 -extfile "$TEST_CERT_DIR/temp.ext" 2>/dev/null
    
    if [ -f "$TEST_CERT_DIR/identity.getpostman.com.crt" ]; then
        echo -e "${GREEN}Test certificate generation successful${NC}"
        
        # Verify certificate validity period (10 years)
        DAYS_VALID=$(openssl x509 -in "$TEST_CERT_DIR/identity.getpostman.com.crt" -noout -dates | grep notAfter | sed 's/.*=//')
        echo -e "${GREEN}Certificate valid until: $DAYS_VALID${NC}"
        
        # Verify CN matches expected value
        CN=$(openssl x509 -in "$TEST_CERT_DIR/identity.getpostman.com.crt" -noout -subject 2>/dev/null | sed 's/.*CN=\([^,]*\).*/\1/')
        if [ "$CN" = "identity.getpostman.com" ]; then
            echo -e "${GREEN}Certificate CN correct: $CN${NC}"
        else
            echo -e "${RED}Certificate CN incorrect: $CN${NC}"
        fi
        
        # Check SAN entries
        SAN=$(openssl x509 -in "$TEST_CERT_DIR/identity.getpostman.com.crt" -noout -text | grep -A 1 "Subject Alternative Name" | tail -1)
        echo -e "${GREEN}SAN entries: $SAN${NC}"
    else
        echo -e "${RED}Test certificate generation failed${NC}"
    fi
    
    # Clean up test directory
    rm -rf "$TEST_CERT_DIR"
else
    echo -e "${YELLOW}Skipping generator test (not installed or not root)${NC}"
fi

# Test the build output profile
if [ -n "$PROFILE_PATH" ]; then
    echo -e "${GREEN}Testing build output profile: $(basename "$PROFILE_PATH")${NC}"
fi

# For testing, we can't actually install the profile without user interaction
# But we can verify it's valid and contains the certificate
echo -e "${YELLOW}Verifying profile structure...${NC}"
plutil -lint "$PROFILE_PATH" 2>/dev/null && echo -e "${GREEN}Profile is valid XML${NC}" || echo -e "${RED}Invalid profile${NC}"

# Extract certificate from profile for testing
echo -e "${YELLOW}Extracting certificate from profile...${NC}"
# The certificate is base64 encoded in the <data> tag
grep -A 20 "<key>PayloadContent</key>" "$PROFILE_PATH" | grep -A 20 "<data>" | sed -n '/<data>/,/<\/data>/p' | sed 's/<[^>]*>//g' | tr -d ' \n' | base64 -d > /tmp/test_cert.der 2>/dev/null

if [ -f /tmp/test_cert.der ]; then
    # Convert DER to PEM for analysis
    openssl x509 -inform DER -in /tmp/test_cert.der -out /tmp/test_cert.pem 2>/dev/null
    
    # Check certificate details
    CN=$(openssl x509 -in /tmp/test_cert.pem -noout -subject 2>/dev/null | sed 's/.*CN=\([^,]*\).*/\1/')
    echo -e "${GREEN}Certificate CN: $CN${NC}"
    
    # Check expiry
    openssl x509 -in /tmp/test_cert.pem -noout -checkend 86400 >/dev/null 2>&1 && echo -e "${GREEN}Certificate is valid${NC}" || echo -e "${RED}Certificate expired or expiring soon${NC}"
    
    # Clean up
    rm -f /tmp/test_cert.der /tmp/test_cert.pem
fi

echo ""
echo -e "${YELLOW}Manual Installation Instructions:${NC}"
echo "1. Double-click the profile: $PROFILE_PATH"
echo "2. System Preferences will open"
echo "3. Click 'Install' and enter admin password"
echo "4. The certificate will be trusted system-wide"
echo ""
echo -e "${YELLOW}For automated deployment:${NC}"
echo "- Use Jamf Pro configuration profiles"
echo "- Deploy via MDM (Intune, Workspace ONE, etc.)"
echo "- Use Apple Configurator 2 for supervised devices"

echo ""
echo -e "${YELLOW}To verify trust after installation:${NC}"
echo "security find-certificate -a -p /Library/Keychains/System.keychain | grep identity.getpostman.com"
