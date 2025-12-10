# Tetragon Control Plane Client

A highly configurable, modular, and robust client for managing Tetragon tracing policies via a centralized control plane.

## Overview

The control plane client connects to a management REST API to:
- Register the client instance with system metadata
- Retrieve versioned tracing policies
- Apply policies to the local Tetragon instance via gRPC
- Report health and status back to the management API

## Features

- **Automatic Registration**: Registers on startup with hostname, instance ID (from IMDSv2 or hostid), environment, architecture, IP address, and custom tags
- **Policy Synchronization**: Periodically fetches policies from the management API and applies them to Tetragon
- **Incremental Updates**: Efficiently applies only changed policies (add/update/delete) instead of replacing all policies
- **Version-based Updates**: Only updates policies when the version or SHA256 hash changes
- **Health Reporting**: Regularly sends client health and policy status to the management API
- **Retry Logic**: Built-in exponential backoff for resilient API communication
- **Configurable**: Extensive configuration options for all client behaviors

## Architecture

```
┌─────────────────────────┐
│  Management API Server  │
│  (REST)                 │
└───────────┬─────────────┘
            │
            │ REST (Register, Get Policies, Report Health)
            │
┌───────────▼─────────────┐
│  Control Plane Client   │
│  - Registration         │
│  - Policy Sync          │
│  - Health Reporter      │
└───────────┬─────────────┘
            │
            │ gRPC (AddTracingPolicy, DeleteTracingPolicy, etc.)
            │
┌───────────▼─────────────┐
│  Tetragon (local)       │
│  gRPC Server            │
└─────────────────────────┘
```

## Configuration

Example configuration file (`config.yaml`):

```yaml
# Management API configuration
management_api:
  base_url: "https://api.example.com/v1"
  auth_token: ""  # Or set via TETRAGON_CONTROL_PLANE_AUTH_TOKEN env var
  timeout: "30s"
  retry:
    max_attempts: 5
    initial_backoff: "1s"
    max_backoff: "60s"
    backoff_multiplier: 2.0

# Tetragon gRPC configuration
tetragon:
  server_address: "localhost:54321"
  timeout: "30s"

# Client registration settings
registration:
  environment: "production"  # dev, stage, live, production
  deployment_type: "standalone"  # standalone or kubernetes
  tags:
    - "region:us-west-2"
    - "team:security"
    - "datacenter:dc1"
  use_imds: true  # Try to get instance_id from IMDSv2
  imds_timeout: "5s"

# Policy synchronization settings
policy_sync:
  enabled: true
  interval: "60s"  # How often to check for policy updates
  cleanup_existing: true  # Remove existing policies on startup
  incremental: true  # Use incremental updates (default: true)

# Health reporting settings
health_reporting:
  enabled: true
  interval: "300s"  # How often to report health

# Logging
logging:
  level: "info"  # debug, info, warn, error
  format: "json"  # json, text
```

## Usage

### Run the client

```bash
# Set auth token via environment variable
export TETRAGON_CONTROL_PLANE_AUTH_TOKEN="your-api-token-here"

./control-plane-client --config config.yaml
```

### Command-line flags

```bash
./control-plane-client \
  --config config.yaml \
  --management-api-url https://api.example.com/v1 \
  --tetragon-address localhost:54321 \
  --environment production \
  --tags region:us-west-2,team:security
```

## API Endpoints

### Registration Endpoint

**POST** `/clients/register`

Request:
```json
{
  "hostname": "node-1.example.com",
  "instance_id": "i-1234567890abcdef0",
  "environment": "production",
  "architecture": "amd64",
  "ip_address": "10.0.1.50",
  "deployment_type": "standalone",
  "tags": ["region:us-west-2", "team:security"]
}
```

Response:
```json
{
  "client_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Get Policies Endpoint

**GET** `/clients/{client_id}/policies`

Response:
```json
{
  "version": "v1.2.3",
  "policies": "base64_encoded_yaml_content",
  "sha256": "a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4"
}
```

The `policies` field contains a base64-encoded YAML document with multiple tracing policies:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sys-write-follow-fd-prefix"
spec:
  ...
---
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "file-monitoring"
spec:
  ...
```

### Health Report Endpoint

**POST** `/clients/{client_id}/health`

Request:
```json
{
  "status": "healthy",
  "policy_version": "v1.2.3",
  "policy_sha256": "a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4",
  "tetragon_version": "v1.0.2",
  "policies": [
    {
      "name": "sys-write-follow-fd-prefix",
      "namespace": "",
      "state": "enabled",
      "error": ""
    },
    {
      "name": "file-monitoring",
      "namespace": "",
      "state": "enabled",
      "error": ""
    }
  ],
  "timestamp": "2025-12-09T10:00:00Z"
}
```

## Building

```bash
cd contrib/control-plane-client
go build -o control-plane-client
```

## Development

Run with debug logging:

```bash
./control-plane-client --config config.yaml --log-level debug
```

## License

Apache 2.0
