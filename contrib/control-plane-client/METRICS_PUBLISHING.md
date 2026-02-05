# Metrics Publishing Specification

## Overview

The control-plane client can collect Prometheus metrics from a Tetragon instance and
publish them to the management API. This enables the control plane to archive or
aggregate metrics emitted by the agent, even when the metrics endpoint is only
reachable locally.

- Scrapes a configurable HTTP(S) endpoint (defaults to `http://localhost:2112/metrics`)
- Wraps the raw payload together with metadata about the source endpoint and format
- POSTs the payload to `POST /clients/{client_id}/metrics` on the management API
- Retries publication using the shared retry logic

## HTTP Endpoint

```
POST /clients/{client_id}/metrics
```

**Authentication**: Bearer token (optional, if configured)  
**Content-Type**: `application/json`

### Request Payload

```json
{
  "format": "prometheus",
  "endpoint": "http://localhost:2112/metrics",
  "payload": "# HELP tetragon_events_total Total number of events\\n# TYPE tetragon_events_total counter\\ntetragon_events_total 42\\n",
  "timestamp": "2025-12-11T14:30:05Z"
}
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `format` | string | Yes | Format of the payload (currently `prometheus`) |
| `endpoint` | string | Yes | Source URL that was scraped. Set this to a remote host if Tetragon runs elsewhere. |
| `payload` | string | Yes | Raw metrics payload, exactly as returned by the scrape endpoint (empty when scraping fails) |
| `timestamp` | string | Yes | ISO 8601 timestamp indicating when the metrics were collected |

## Collection Flow

1. The metrics publisher issues an HTTP GET to the configured `metrics_publishing.endpoint`.
2. TLS verification can be disabled per config for development/testing (not recommended for production).
3. On success, the payload is streamed as-is into a `MetricsReport`.
4. On scrape failure, the client logs a warning, sends an empty payload, and health reporting marks `"degraded:metrics_scrape_err"`.
5. The client sends the report to the management API using the standard retry policy.
6. Consecutive publication errors trigger exponential backoff before the next attempt.

## Configuration

```yaml
metrics_publishing:
  enabled: true
  interval: "60s"
  endpoint: "http://localhost:2112/metrics"
  request_timeout: "10s"
  format: "prometheus"
  insecure_skip_tls_verify: false
```

| Field | Description |
|-------|-------------|
| `enabled` | Turns metrics publishing on/off. |
| `interval` | Base interval between scrape/publish cycles (jitter and backoff are applied automatically). |
| `endpoint` | Full URL of the Prometheus metrics endpoint. Set this to the remote machine's address when Tetragon does not run locally. |
| `request_timeout` | Timeout for scraping the metrics endpoint. |
| `format` | Label describing the payload format sent to the control plane. |
| `insecure_skip_tls_verify` | Skip TLS certificate verification when scraping HTTPS endpoints (development only). |

## Extensibility Considerations

- The endpoint is expressed as a full URL, so the client can scrape any reachable host/port/path combination.
- The format string is included in the payload, allowing future parsers to accept additional formats.
- The HTTP client is isolated from the management API client, keeping scrape-specific settings independent from API communication.
