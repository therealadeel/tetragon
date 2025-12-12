# Health Reporting Specification

## Overview

The control-plane client periodically reports the health status of Tetragon and its loaded tracing policies to the management API. This document describes the health reporting mechanism, data structures, and status determination logic.

## Health Report Structure

### HTTP Endpoint

```
POST /clients/{client_id}/health
```

**Authentication**: Bearer token (optional, if configured)

**Content-Type**: `application/json`

### Request Payload

```json
{
  "status": "healthy", // or degraded
  "policy_display_name": "2024-12-11-14:30-a3f2e8b9c1d4",
  "policy_sha256": "a3f2e8b9c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c2d4e6f8a0b2c4d6e8f0",
  "tetragon_version": "v1.2.3",
  "policies": [
    {
      "name": "file-monitoring",
      "namespace": "default",
      "state": "TP_STATE_ENABLED",
      "error": ""
    },
    {
      "name": "network-policy",
      "namespace": "",
      "state": "TP_STATE_ENABLED",
      "error": ""
    }
  ],
  "timestamp": "2024-12-11T14:30:00Z"
}
```

### Response

**Success**: HTTP 200 OK or 202 Accepted (no body required)

**Failure**: HTTP 4xx/5xx with error message in body

## Data Fields

### Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `status` | string | Yes | Overall health status: `"healthy"` or `"degraded"` |
| `policy_display_name` | string | Yes | Human-friendly identifier for current policy set (e.g., timestamp + short hash) |
| `policy_sha256` | string | Yes | Full SHA256 hash of currently applied policies |
| `tetragon_version` | string | Yes | Version of Tetragon server (e.g., "v1.2.3" or "unknown" if unavailable) |
| `policies` | array | Yes | Array of individual policy statuses (may be empty) |
| `timestamp` | string | Yes | ISO 8601 timestamp when report was generated |

### Policy Status Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Name of the tracing policy |
| `namespace` | string | Yes | Kubernetes namespace (empty string for global policies) |
| `state` | string | Yes | Current state from Tetragon (see Policy States below) |
| `error` | string | Yes | Error message if state indicates failure (empty string otherwise) |

## Policy States

Policy states are derived from Tetragon's gRPC API (`TracingPolicyState` enum):

| State | Value | Description | Considered Healthy? |
|-------|-------|-------------|---------------------|
| `TP_STATE_ENABLED` | 1 | Policy is loaded and actively monitoring | ✅ Yes |
| `TP_STATE_UNKNOWN` | 0 | State cannot be determined | ❌ No |
| `TP_STATE_DISABLED` | 2 | Policy is loaded but not active | ❌ No |
| `TP_STATE_LOAD_ERROR` | 3 | Failed to load policy | ❌ No |
| `TP_STATE_ERROR` | 4 | Error occurred during policy lifetime | ❌ No |
| `TP_STATE_LOADING` | 5 | Policy is currently being loaded | ❌ No |
| `TP_STATE_UNLOADING` | 6 | Policy is currently being unloaded | ❌ No |

## Health Status Determination

The overall `status` field is determined by the following logic:

### Algorithm

```go
status = "healthy"  // Start with healthy assumption

for each policy in policies:
    if policy.state != "TP_STATE_ENABLED":
        status = "degraded"
        break  // Stop checking, already degraded
```

### Status Values

**`"healthy"`**:
- All policies have `state = "TP_STATE_ENABLED"`
- No policies have non-empty `error` fields
- Tetragon is operational and all policies are functioning correctly

**`"degraded"`**:
- At least one policy has `state != "TP_STATE_ENABLED"`
- Indicates partial system functionality
- Some policies may be failing, loading, or disabled

### Edge Cases

1. **No Policies**: If `policies` array is empty, status is `"healthy"` (no policies to fail)
2. **Tetragon Version Unknown**: Version field set to `"unknown"`, but doesn't affect health status
3. **Policy Errors**: Non-empty `error` field doesn't automatically set degraded status, only `state` matters

## Data Collection Process

### Implementation Flow

1. **Version Collection**:
   ```
   tetragon.GetVersion() → "v1.2.3"
   ```
   - If fails: logs warning, uses `"unknown"`

2. **Policy Status Collection**:
   ```
   tetragon.ListTracingPolicies() → []TracingPolicyStatus
   ```
   - Retrieves all loaded policies from Tetragon gRPC API
   - Converts each policy to simplified `PolicyStatus` format
   - If fails: returns error, health report not sent

3. **Cached Policy Information**:
   ```
   cache.GetPolicyDisplayName() → "2024-12-11-14:30-a3f2e8b9c1d4"
   cache.GetPolicySha256() → "a3f2e8b9c1d4e5f6a7b8c9d0e1f2a3b4..."
   ```
   - Reflects the policy set that was last successfully applied
   - May differ from current Tetragon state if manual changes occurred

4. **Status Determination**:
   - Iterates through all policy statuses
   - Checks each `state` field
   - Sets `"degraded"` on first non-enabled policy
   - Logs warning for degraded policies

5. **Report Transmission**:
   - Marshals report to JSON
   - POSTs to management API endpoint
   - Includes Bearer token authentication if configured
   - Retries on transient failures (per retry configuration)

## Logging Behavior

### Before Sending

The client logs detailed information before transmission:

```
INFO sending health report to management API: client_id=abc123, status=healthy, 
     policy_display_name=2024-12-11-14:30-a3f2e8b9, policy_sha256=a3f2e8b9c1d4..., 
     tetragon_version=v1.2.3, policies_count=5
```

### Per-Policy Debug Logs

For each policy (when debug logging enabled):

```
DEBUG policy 0: name=file-monitoring, state=TP_STATE_ENABLED, error=
DEBUG policy 1: name=network-policy, state=TP_STATE_ENABLED, error=
```

### Degraded Status Warning

When a policy is not enabled:

```
WARN policy file-monitoring state is TP_STATE_LOADING (not TP_STATE_ENABLED), marking as degraded
```

### After Success

```
INFO health report successfully sent: status=healthy, policies=5
```

### On Failure

Errors are tracked and cause exponential backoff on the next health reporting cycle.

## Error Handling

### Consecutive Error Tracking

The HealthReporter maintains a counter of consecutive failures:

- **Incremented on**: 
  - Failure to get policy statuses from Tetragon
  - Failure to send report to management API

- **Reset to 0 on**: 
  - Successful report transmission

- **Effect**: 
  - Used for exponential backoff calculation
  - Next health report interval increased by `2^consecutiveErrors * baseInterval`
  - Capped at 5 errors (10 minutes maximum additional delay)

### Failure Scenarios

| Scenario | Behavior | Health Report Sent? |
|----------|----------|---------------------|
| Tetragon version unavailable | Uses `"unknown"`, continues | ✅ Yes |
| Cannot get policy statuses | Returns error, increments counter | ❌ No |
| API request fails | Returns error, increments counter | ❌ No |
| Policy in non-enabled state | Marks degraded, sends report | ✅ Yes |

## Reporting Frequency

### Configuration

Controlled by `health_reporting.interval` in configuration:

```yaml
health_reporting:
  interval: 75s  # Report every 75 seconds
```

### Dynamic Adjustment

With backpressure enabled:
- Base interval: 75 seconds
- Jitter: ±20% (60-90 seconds)
- On consecutive errors: interval increases exponentially
- On success: resets to base interval with jitter

### Example Timing

| Consecutive Errors | Additional Delay | Effective Interval |
|-------------------|------------------|-------------------|
| 0 | 0s | 75s ± 20% |
| 1 | 2¹ × 75s = 150s | 225s ± 20% |
| 2 | 2² × 75s = 300s | 375s ± 20% |
| 3 | 2³ × 75s = 600s | 675s ± 20% |
| 4 | 2⁴ × 75s = 1200s | 1275s ± 20% |
| 5+ | Capped at 600s | 675s ± 20% |

## Integration Points

### Tetragon gRPC API

**Methods Used**:
- `GetVersion()` → Returns Tetragon version string
- `ListTracingPolicies()` → Returns array of `TracingPolicyStatus` objects

**Proto Definition**: `github.com/cilium/tetragon/api/v1/tetragon`

### Management API

**Expected Endpoint**: `POST /clients/{client_id}/health`

**Authentication**: Optional Bearer token via `Authorization` header

**Expected Response**: HTTP 200 OK or 202 Accepted

## Use Cases

### Monitoring Dashboard

Management API can use health reports to:
- Display real-time status of all clients
- Alert on degraded policies
- Track policy deployment success rates
- Monitor Tetragon version distribution

### Automated Remediation

On receiving `"degraded"` status:
- Identify failing policies from `policies` array
- Check `error` field for diagnostics
- Trigger policy redeployment if needed
- Alert operations team

### Compliance Auditing

Health reports provide evidence of:
- Which policies are active at any given time
- Policy version history (via `policy_sha256`)
- System uptime and stability
- Policy change tracking

## Example Scenarios

### Scenario 1: All Policies Healthy

```json
{
  "status": "healthy",
  "policy_display_name": "prod-v5-a3f2e8b9c1d4",
  "policy_sha256": "a3f2e8b9c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c2d4e6f8a0b2c4d6e8f0",
  "tetragon_version": "v1.2.3",
  "policies": [
    {"name": "file-monitoring", "namespace": "default", "state": "TP_STATE_ENABLED", "error": ""},
    {"name": "network-policy", "namespace": "security", "state": "TP_STATE_ENABLED", "error": ""}
  ],
  "timestamp": "2024-12-11T14:30:00Z"
}
```

**Interpretation**: System is fully operational with 2 active policies.

### Scenario 2: Policy Loading

```json
{
  "status": "degraded",
  "policy_display_name": "prod-v6-b4c5d6e7f8a9",
  "policy_sha256": "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5",
  "tetragon_version": "v1.2.3",
  "policies": [
    {"name": "file-monitoring", "namespace": "default", "state": "TP_STATE_ENABLED", "error": ""},
    {"name": "new-policy", "namespace": "default", "state": "TP_STATE_LOADING", "error": ""}
  ],
  "timestamp": "2024-12-11T14:35:00Z"
}
```

**Interpretation**: New policy is being loaded, system temporarily degraded.

### Scenario 3: Policy Error

```json
{
  "status": "degraded",
  "policy_display_name": "prod-v7-c5d6e7f8a9b0",
  "policy_sha256": "c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "tetragon_version": "v1.2.3",
  "policies": [
    {"name": "file-monitoring", "namespace": "default", "state": "TP_STATE_ENABLED", "error": ""},
    {"name": "bad-policy", "namespace": "default", "state": "TP_STATE_ERROR", 
     "error": "failed to load BPF program: invalid instruction"}
  ],
  "timestamp": "2024-12-11T14:40:00Z"
}
```

**Interpretation**: One policy failed with specific error, immediate attention required.

### Scenario 4: No Policies

```json
{
  "status": "healthy",
  "policy_display_name": "",
  "policy_sha256": "",
  "tetragon_version": "v1.2.3",
  "policies": [],
  "timestamp": "2024-12-11T14:45:00Z"
}
```

**Interpretation**: Tetragon is running but no policies are loaded (initial state or after cleanup).

## Security Considerations

1. **Authentication**: Bearer token should be transmitted over HTTPS only
2. **Data Sensitivity**: Health reports may reveal infrastructure details
3. **Rate Limiting**: Management API should rate-limit health report endpoints
4. **Policy Names**: May contain sensitive information about security monitoring
5. **Error Messages**: Avoid exposing internal system details in error fields

## Troubleshooting

### Health Reports Not Received

**Check**:
1. Client logs for "sending health report to management API" messages
2. Consecutive error count in logs
3. Network connectivity to management API
4. Authentication token validity
5. Management API endpoint availability

### Always Reporting Degraded

**Check**:
1. Policy states in health report logs
2. Tetragon logs for policy loading issues
3. Policy YAML syntax and validity
4. Resource constraints (memory, CPU) on Tetragon

### Stale Policy Information

**Check**:
1. `policy_sha256` matches expected value
2. Policy sync logs for successful updates
3. Cache state via debug logs
4. Manual changes to Tetragon outside of control-plane client

## Related Documentation

- [IMPLEMENTATION.md](./IMPLEMENTATION.md) - Overall architecture
- [README.md](./README.md) - User guide and configuration
- [LOG_ROTATION.md](./LOG_ROTATION.md) - Logging configuration
- Tetragon API Documentation: `github.com/cilium/tetragon/api/v1/tetragon`
