# Testing Guide

This guide provides instructions for testing the Tetragon Control Plane Client.

## Prerequisites

1. **Tetragon running locally**:
   ```bash
   # Start Tetragon with default settings
   sudo tetragon --bpf-lib /usr/local/lib/tetragon/
   ```

2. **Mock Management API Server** (for testing):
   You'll need to create a simple mock server that implements the required endpoints.

Run the mock server:

**Without authentication (for basic testing):**
```bash
go run test-server.go
```

**With authentication (recommended for production-like testing):**
```bash
export API_AUTH_TOKEN="test-secret-token-12345"
go run test-server.go
```

The server will validate the `Authorization: Bearer <token>` header on all requests when `API_AUTH_TOKEN` is set.

## Authentication Configuration

The control plane client supports token-based authentication via the management API. The server MUST validate authentication tokens to ensure secure communication.

### Server-Side Authentication

The mock server implements Bearer token authentication:

1. **Token Validation**: The server checks the `Authorization` header for a Bearer token
2. **Environment-based Configuration**: Set `API_AUTH_TOKEN` on the server to enable authentication
3. **Secure Responses**: Returns HTTP 401 Unauthorized for missing or invalid tokens

### Client-Side Authentication

Configure the client to send authentication tokens:

**Via configuration file:**
```yaml
management_api:
  base_url: "http://localhost:8080/v1"
  auth_token: "test-secret-token-12345"  # Not recommended for production
  # ... other settings
```

**Via environment variable (recommended):**
```bash
export TETRAGON_CONTROL_PLANE_AUTH_TOKEN="test-secret-token-12345"
./control-plane-client --config config-test.yaml
```

**Security Note**: Always use environment variables or secure secret management systems for authentication tokens in production. Never commit tokens to version control.

## Testing Steps

### 1. Build the Client

```bash
cd contrib/control-plane-client
make build
```

### 2. Create Test Configuration

Copy the example config and modify:

```bash
cp config-example.yaml config-test.yaml
```

Edit `config-test.yaml`:
```yaml
management_api:
  base_url: "http://localhost:8080/v1"
  auth_token: ""  # Leave empty, use environment variable instead
  timeout: "30s"
  retry:
    max_attempts: 3
    initial_backoff: "1s"
    max_backoff: "10s"
    backoff_multiplier: 2.0

tetragon:
  server_address: "localhost:54321"
  timeout: "30s"

registration:
  environment: "dev"
  tags:
    - "test:true"
    - "local:dev"
  use_imds: false  # Disable IMDS for local testing

policy_sync:
  enabled: true
  interval: "30s"
  cleanup_existing: true

health_reporting:
  enabled: true
  interval: "60s"

cache:
  client_id_file: "/tmp/tetragon-cp-client/client_id"
  policy_version_file: "/tmp/tetragon-cp-client/policy_version"

logging:
  level: "debug"
  format: "text"
```

### 3. Run the Client

**With authentication:**
```bash
export TETRAGON_CONTROL_PLANE_AUTH_TOKEN="test-secret-token-12345"
./control-plane-client --config config-test.yaml
```

**Without authentication (if server doesn't require it):**
```bash
./control-plane-client --config config-test.yaml
```

### 4. Expected Output

You should see:
1. Client registration with the mock API
2. Connection to Tetragon
3. Cleanup of existing policies (if any)
4. Initial policy synchronization
5. Periodic policy checks every 30s
6. Health reports every 60s

### 5. Verify Policies in Tetragon

In another terminal:

```bash
# List policies using tetra CLI
tetra tracingpolicy list

# You should see the policies from example-policies.yaml
```

### 6. Test Policy Updates

1. Modify `example-policies.yaml` 
2. Change the version in the mock server's `handleGetPolicies` function
3. Wait for the next sync interval
4. The client should detect the version change and update policies
5. Observe the new SHA256 hash logged by both server and client

## Manual Testing Scenarios

### Test Authentication

**Test with valid token:**
```bash
# Start server with authentication
export API_AUTH_TOKEN="test-secret-token-12345"
go run test-server.go

# In another terminal, run client with matching token
export TETRAGON_CONTROL_PLANE_AUTH_TOKEN="test-secret-token-12345"
./control-plane-client --config config-test.yaml

# Expected: Successful registration and policy sync
```

**Test with invalid token:**
```bash
# Server still running with API_AUTH_TOKEN="test-secret-token-12345"

# Run client with wrong token
export TETRAGON_CONTROL_PLANE_AUTH_TOKEN="wrong-token"
./control-plane-client --config config-test.yaml

# Expected: HTTP 401 errors, client will retry with exponential backoff
```

**Test without token when required:**
```bash
# Server still running with API_AUTH_TOKEN set

# Run client without token
unset TETRAGON_CONTROL_PLANE_AUTH_TOKEN
./control-plane-client --config config-test.yaml

# Expected: HTTP 401 errors (missing Authorization header)
```

### Test Registration

```bash
# Clear cache
rm -rf /tmp/tetragon-cp-client/

# Run client - should register and cache client ID
./control-plane-client --config config-test.yaml

# Stop client (Ctrl+C)
# Run again - should use cached client ID
./control-plane-client --config config-test.yaml
```

### Test Policy Cleanup

```bash
# Load some policies manually
tetra tracingpolicy add example-policies.yaml

# Run client with cleanup_existing: true
./control-plane-client --config config-test.yaml

# Policies should be removed and reloaded from management API
```

### Test Retry Logic

```bash
# Stop the mock server
# Run client - should retry connection with exponential backoff
./control-plane-client --config config-test.yaml

# Start mock server
# Client should eventually succeed
```

### Test Command-Line Overrides

```bash
./control-plane-client \
  --config config-test.yaml \
  --environment production \
  --tags "override:test,local:false" \
  --log-level debug
```

## Troubleshooting

### "Failed to connect to Tetragon"

- Ensure Tetragon is running: `sudo tetragon`
- Check Tetragon is listening on port 54321: `lsof -i :54321`

### "Registration failed"

- Ensure mock server is running: `curl http://localhost:8080/v1/clients/register`
- Check logs in both client and server
- **Verify authentication token matches**: If server requires auth, ensure `TETRAGON_CONTROL_PLANE_AUTH_TOKEN` is set correctly
- **Check Authorization header**: Use curl to test manually:
  ```bash
  curl -X POST http://localhost:8080/v1/clients/register \
    -H "Authorization: Bearer test-secret-token-12345" \
    -H "Content-Type: application/json" \
    -d '{"hostname":"test","instance_id":"123","environment":"dev","architecture":"amd64","ip_address":"127.0.0.1","tags":[]}'
  ```

### "Failed to apply policies"

- Check YAML syntax in example-policies.yaml
- Verify policies are valid: `tetra tracingpolicy add example-policies.yaml`

## Cleanup

```bash
# Stop client (Ctrl+C)
# Stop mock server (Ctrl+C)
# Remove cache
rm -rf /tmp/tetragon-cp-client/
# Remove policies from Tetragon
tetra tracingpolicy delete file-monitoring
tetra tracingpolicy delete network-connections
```
