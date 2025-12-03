#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
ADMIN_SECRET="${ADMIN_SECRET:-${API_TOKEN_CREATION_SECRET:-CHANGE_ME}}"

# Check if jq is available
if command -v jq &> /dev/null; then
    JQ_CMD="jq '.'"
else
    echo "Warning: jq not found. JSON output will not be formatted."
    JQ_CMD="cat"
fi

echo ">>> Health check"
curl -sSf "$BASE_URL/health" | eval "$JQ_CMD"

echo ""
echo ">>> Create API token"
TOKEN_RESPONSE=$(curl -sSf \
  -H "X-LabCA-Admin-Secret: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "api-smoke-test-token",
    "permissions": {
      "issue": true,
      "read": true,
      "revoke": false
    }
  }' \
  "$BASE_URL/api/v1/tokens")

echo "$TOKEN_RESPONSE" | eval "$JQ_CMD"

# Extract token from response
if command -v jq &> /dev/null; then
    API_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.token // empty')
else
    # Fallback: try to extract token using grep/sed (basic extraction)
    API_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"token"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || echo "")
fi

if [ -z "$API_TOKEN" ] || [ "$API_TOKEN" = "null" ]; then
  echo "ERROR: Failed to create API token. Response:"
  echo "$TOKEN_RESPONSE"
  echo ""
  echo "NOTE: Make sure API_TOKEN_CREATION_SECRET is set in the server environment."
  echo "      You can set it via environment variable or .env file."
  echo "      Also ensure ADMIN_SECRET or API_TOKEN_CREATION_SECRET env var is set for this script."
  exit 1
fi

# Extract token prefix
if command -v jq &> /dev/null; then
    TOKEN_PREFIX=$(echo "$TOKEN_RESPONSE" | jq -r '.token_prefix // "unknown"')
else
    TOKEN_PREFIX=$(echo "$TOKEN_RESPONSE" | grep -o '"token_prefix"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"token_prefix"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || echo "unknown")
fi

echo ""
echo ">>> API token created successfully (prefix: $TOKEN_PREFIX)"

echo ""
echo ">>> Issue self-signed cert via API"
CERT_RESPONSE=$(curl -sSf \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "issuer_ca_id": null,
    "common_name": "api.example.local",
    "dns_sans": ["api.example.local"],
    "key_algorithm": "RSA",
    "key_size": 2048,
    "hash_algorithm": "SHA256",
    "validity_days": 30,
    "usage_preset": "server_tls",
    "return_private_key": true
  }' \
  "$BASE_URL/api/v1/certificates")

echo "$CERT_RESPONSE" | eval "$JQ_CMD" | tee /tmp/api_cert_response.json

# Also save raw response for parsing
echo "$CERT_RESPONSE" > /tmp/api_cert_response_raw.json

# Validate response
if command -v jq &> /dev/null; then
    CERT_ID=$(echo "$CERT_RESPONSE" | jq -r '.certificate_id // empty')
    CERT_PEM=$(echo "$CERT_RESPONSE" | jq -r '.certificate_pem // empty')
else
    # Fallback extraction
    CERT_ID=$(echo "$CERT_RESPONSE" | grep -o '"certificate_id"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"certificate_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || echo "")
    CERT_PEM=$(echo "$CERT_RESPONSE" | grep -o '"certificate_pem"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"certificate_pem"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || echo "")
fi

if [ -z "$CERT_ID" ] || [ "$CERT_ID" = "null" ]; then
  echo "ERROR: Certificate ID not found in response"
  exit 1
fi

if [ -z "$CERT_PEM" ] || [ "$CERT_PEM" = "null" ]; then
  echo "ERROR: Certificate PEM not found in response"
  exit 1
fi

echo ""
echo ">>> Certificate issued successfully (ID: $CERT_ID)"

echo ""
echo ">>> Retrieve certificate via GET"
GET_RESPONSE=$(curl -sSf \
  -H "Authorization: Bearer $API_TOKEN" \
  "$BASE_URL/api/v1/certificates/$CERT_ID")

echo "$GET_RESPONSE" | eval "$JQ_CMD"

# Validate retrieved certificate
if command -v jq &> /dev/null; then
    RETRIEVED_CERT_PEM=$(echo "$GET_RESPONSE" | jq -r '.certificate_pem // empty')
else
    RETRIEVED_CERT_PEM=$(echo "$GET_RESPONSE" | grep -o '"certificate_pem"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"certificate_pem"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || echo "")
fi
if [ -z "$RETRIEVED_CERT_PEM" ] || [ "$RETRIEVED_CERT_PEM" = "null" ]; then
  echo "ERROR: Certificate PEM not found in GET response"
  exit 1
fi

echo ""
echo ">>> All API smoke tests passed!"

