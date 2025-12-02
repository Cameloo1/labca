# API Smoke Test Scripts

This directory contains scripts for testing the LabCA API endpoints from the outside, simulating real external consumers.

## Prerequisites

1. **LabCA server must be running**
   ```bash
   uvicorn app.main:app --reload
   ```

2. **Environment variables** (optional):
   - `BASE_URL` - API base URL (default: `http://localhost:8000`)
   - `ADMIN_SECRET` or `API_TOKEN_CREATION_SECRET` - Secret for creating API tokens
   - `API_TOKEN` - Existing API token to use (optional, script will create one if not provided)

3. **Dependencies**:
   - `requests` Python library (for `api_test.py`)
   - `jq` command-line tool (for `api_smoke.sh` - optional but recommended)
   - `curl` (for `api_smoke.sh`)

## Scripts

### `api_smoke.sh` - Bash/Curl Script

Tests API endpoints using curl commands.

**Usage:**
```bash
# Make executable (Unix/Linux/Mac)
chmod +x scripts/api_smoke.sh

# Run with defaults
./scripts/api_smoke.sh

# Run with custom base URL and admin secret
BASE_URL=http://localhost:8000 ADMIN_SECRET=your-secret ./scripts/api_smoke.sh
```

**On Windows:**
- Use Git Bash, WSL, or PowerShell with curl installed
- Or use the Python script instead

**What it tests:**
1. Health check endpoint
2. API token creation
3. Self-signed certificate issuance
4. Certificate retrieval by ID

### `api_test.py` - Python Script

Tests API endpoints using the `requests` library with detailed validation.

**Usage:**
```bash
# Run with defaults
python scripts/api_test.py

# Run with custom base URL and admin secret
BASE_URL=http://localhost:8000 ADMIN_SECRET=your-secret python scripts/api_test.py

# Use existing API token (skips token creation)
API_TOKEN=your-token python scripts/api_test.py
```

**What it tests:**
1. Health check endpoint
2. API token creation (unless `API_TOKEN` is provided)
3. Self-signed certificate issuance
4. Certificate validation using `cryptography` library:
   - Common Name (CN)
   - Validity period
   - Current validity status
5. Certificate retrieval by ID
6. Prints JSON summary of all tests

## Example Output

Both scripts will:
- Test the `/health` endpoint
- Create an API token with issue and read permissions
- Issue a self-signed certificate for `api.example.local`
- Retrieve the certificate by ID
- Validate the certificate structure

## Troubleshooting

**Connection refused:**
- Make sure the LabCA server is running
- Check that `BASE_URL` points to the correct address

**403 Forbidden when creating token:**
- Ensure `ADMIN_SECRET` or `API_TOKEN_CREATION_SECRET` is set correctly
- The secret must match the `API_TOKEN_CREATION_SECRET` environment variable used when starting the server

**401 Unauthorized:**
- Token creation may have failed
- Check the token creation response for errors

**Certificate validation fails:**
- Check that the certificate PEM is valid
- Verify the certificate is within its validity period

