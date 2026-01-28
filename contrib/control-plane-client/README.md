# Tetragon Control Plane Client

A highly configurable, modular, and robust client for managing Tetragon tracing policies via a centralized control plane.

## Overview

The control plane client connects to a Splunk App instance REST API to:
- Register the client instance with system metadata
- Retrieve versioned tracing policies
- Apply policies to the local Tetragon instance via gRPC
- Report health and status back to the management API

## Features

- **Automatic Registration**: Registers on startup with hostname, instance ID (from IMDSv2 or hostid), environment, architecture, IP address, and custom tags
- **Policy Synchronization**: Periodically fetches policies from the Splunk App API and applies them to Tetragon
- **Incremental Updates**: Efficiently applies only changed policies (add/update/delete) instead of replacing all policies, based on SHA256 hashes of the rendered policy YAML
- **Health Reporting**: Regularly sends client health and policy status (including the active policy SHA) to the management API
- **Metrics Publishing**: Scrapes local or remote Prometheus metrics and forwards them to the management API
- **Retry Logic**: Built-in exponential backoff for resilient API communication
- **Configurable**: Extensive configuration options for all client behaviors

## Architecture

```
┌─────────────────────────┐
│  Management API Server  │
│  (Splunk)               │
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
  base_url: "https://api.example.com:8089/servicesNS/nobody/tetragon_control_plane/v1"
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
  environment: "production"
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

# Health reporting settings
health_reporting:
  enabled: true
  interval: "300s"  # How often to report health

# Metrics publishing settings
metrics_publishing:
  enabled: true
  interval: "60s"  # How often to collect and forward metrics
  endpoint: "http://localhost:2112/metrics"  # Set to remote host if Tetragon runs elsewhere
  request_timeout: "10s"
  format: "prometheus"
  insecure_skip_tls_verify: false

# Logging
logging:
  level: "info"  # debug, info, warn, error
  format: "json"  # json, text
```

> **Note:** Incremental policy synchronization is always enabled. The `policy_sync.incremental` option is currently ignored.

## Usage

### Run the client

```bash
# Set Splunk auth token via environment variable
export TETRAGON_CONTROL_PLANE_AUTH_TOKEN="your-api-token-here"

./control-plane-client --config config.yaml
```

### Command-line flags

```bash
./control-plane-client \
  --config config.yaml \
  --management-api-url https://api.example.com:8089/servicesNS/nobody/tetragon_control_plane/v1 \
  --tetragon-address localhost:54321 \
  --environment production \
  --tag region:us-west-2 \
  --tag team:security
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
  "display_name": "2025-01-15-18:30-a3b5c7d9e1f2",
  "policies": "base64_encoded_yaml_content",
  "sha256": "a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8f0a2b4",
  "policy_count": 2
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
  "policy_display_name": "2025-01-15-18:30-a3b5c7d9e1f2",
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

### Metrics Report Endpoint

**POST** `/clients/{client_id}/metrics`

The client scrapes Prometheus metrics (default `http://localhost:2112/metrics`) and forwards the raw payload.

Request:
```json
{
  "format": "prometheus",
  "endpoint": "http://localhost:2112/metrics",
  "payload": "# HELP tetragon_events_total Total number of events\\n# TYPE tetragon_events_total counter\\ntetragon_events_total 42\\n",
  "timestamp": "2025-12-09T10:00:05Z"
}
```

Configure `metrics_publishing.endpoint` to target a remote host or non-default path when Tetragon runs on another machine.

## Additional Documentation

- `HEALTH_REPORTING.md` – detailed description of the health payload and evaluation logic.
- `METRICS_PUBLISHING.md` – specification for the metrics publisher, payload format, and configuration.

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
