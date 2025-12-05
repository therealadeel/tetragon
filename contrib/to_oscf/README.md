# Tetragon to OCSF Converter

A tool that converts Tetragon security observability events into [Open Cybersecurity Schema Framework (OCSF)](https://github.com/ocsf/ocsf-schema) format for standardized security event logging and analysis.

## Overview

This converter maps Tetragon's eBPF-based security events to OCSF's standardized schema, enabling:
- **Standardized Security Events**: Consistent format across security tools
- **Enhanced Analytics**: Better correlation and analysis in SIEM/SOAR platforms  
- **Vendor Interoperability**: Standard format not tied to specific vendors
- **Compliance**: Meet requirements for standardized security logging

## OCSF Event Mappings

| Tetragon Event Type | OCSF Category | OCSF Class | OCSF Activity |
|---------------------|---------------|------------|---------------|
| ProcessExec | System Activity (1) | Process Activity (1007) | Launch (1) |
| ProcessExit | System Activity (1) | Process Activity (1007) | Terminate (2) |
| ProcessKprobe (syscalls) | System Activity (1) | Kernel Activity (1003) | System Call (1) |
| ProcessKprobe (file ops) | System Activity (1) | File System Activity (1001) | Create/Read/Write/etc |
| ProcessTracepoint | System Activity (1) | Kernel Activity (1003) | System Call (1) |
| ProcessUprobe | Application Activity (6) | Process Activity (1007) | Access (3) |

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Tetragon      │    │   to_oscf        │    │   OCSF Events   │
│   gRPC Stream   │───▶│   Converter      │───▶│   JSON Output   │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │   Configuration  │
                       │   (YAML)         │
                       └──────────────────┘
```

## Installation

```bash
# Build the converter
cd contrib/to_oscf
make build

# Or build with Go directly
go build -o to_oscf main.go
```

## Usage

### Basic Usage

```bash
# Convert events to console (stdout)
./to_oscf

# Convert with custom Tetragon server
TETRAGON_SERVER=tetragon.example.com:54321 ./to_oscf

# Convert with custom configuration
./to_oscf -config config.yaml
```

### Output to File

```bash
# Output to specific file
OCSF_OUTPUT_FILE=/var/log/tetragon-ocsf.json ./to_oscf

# Output to directory (creates tetragon-ocsf.json)
TETRAGON_EXPORT_DIR=/var/log ./to_oscf
```

### Docker Usage

```bash
# Run in Docker with volume mount
docker run --rm -v /tmp:/output \
  -e TETRAGON_EXPORT_DIR=/output \
  -e TETRAGON_SERVER=host.docker.internal:54321 \
  tetragon-to-ocsf:latest
```

## Configuration

The converter uses a YAML configuration file:

```yaml
tetragon:
  server_address: "localhost:54321"

output:
  format: "json"
  indent: true

ocsf:
  schema_version: "1.7.0"
  product:
    name: "Tetragon"
    vendor: "Cilium"
    version: "1.0.0"
    feature: "Runtime Security Observability"
    uid: "tetragon-001"
  
  metadata:
    environment: "production"
    datacenter: "us-west-2"
    deployment: "kubernetes"
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TETRAGON_SERVER` | Tetragon gRPC server address | `localhost:54321` |
| `OCSF_OUTPUT_FILE` | Output file path | stdout |
| `TETRAGON_EXPORT_DIR` | Output directory (creates tetragon-ocsf.json) | - |

## Sample OCSF Output

### Process Execution Event
```json
{
  "category_uid": 1,
  "category_name": "System Activity", 
  "class_uid": 1007,
  "class_name": "Process Activity",
  "activity_id": 1,
  "activity_name": "Launch",
  "type_uid": 100701,
  "type_name": "Process Activity: Launch",
  "severity_id": 1,
  "severity": "Informational",
  "message": "Process started: /usr/bin/vim",
  "time": 1701728400,
  "timestamp": "2023-12-04T20:00:00.000Z",
  "metadata": {
    "version": "1.7.0",
    "product": {
      "name": "Tetragon",
      "vendor_name": "Cilium",
      "version": "1.0.0",
      "feature": "Runtime Security Observability"
    },
    "correlation_uid": {
      "exec_id": "bGltYS10ZXRyYWdvbjo..."
    }
  },
  "device": {
    "hostname": "workstation-01",
    "name": "workstation-01",
    "type": "Computer",
    "os": {
      "name": "Linux",
      "type": "Linux"
    }
  },
  "process": {
    "name": "vim",
    "pid": 12345,
    "uid": "1000",
    "cmd_line": "vim /etc/hosts",
    "created_time": "2023-12-04T20:00:00.000Z",
    "file": {
      "path": "/usr/bin/vim",
      "name": "vim"
    },
    "user": {
      "uid": "1000"
    }
  },
  "parent": {
    "name": "bash",
    "pid": 12340,
    "uid": "1000",
    "file": {
      "path": "/bin/bash",
      "name": "bash"
    }
  }
}
```

### File System Activity Event
```json
{
  "category_uid": 1,
  "category_name": "System Activity",
  "class_uid": 1001, 
  "class_name": "File System Activity",
  "activity_id": 3,
  "activity_name": "Write",
  "type_uid": 100103,
  "type_name": "File System Activity: Write",
  "message": "File write: /etc/hosts",
  "file": {
    "path": "/etc/hosts",
    "name": "hosts"
  },
  "enrichments": {
    "syscall": {
      "function_name": "__arm64_sys_write",
      "policy_name": "file-monitoring",
      "action": "KPROBE_ACTION_POST"
    }
  }
}
```

## Integration Examples

### Splunk Integration
```bash
# Output to Splunk Universal Forwarder
OCSF_OUTPUT_FILE=/opt/splunkforwarder/var/spool/splunk/tetragon-ocsf.json ./to_oscf
```

### ELK Stack Integration  
```bash
# Output for Filebeat/Logstash ingestion
TETRAGON_EXPORT_DIR=/var/log/ocsf ./to_oscf
```

### SIEM Integration
```bash
# Output with structured logging for SIEM ingestion
./to_oscf -config production-config.yaml > /var/log/siem/tetragon-ocsf.log
```

## OCSF Schema Compliance

This converter implements OCSF v1.7.0 with:
- ✅ Core event structure 
- ✅ System Activity category
- ✅ Process Activity class
- ✅ File System Activity class  
- ✅ Kernel Activity class
- ✅ Metadata and correlation
- ✅ Device and actor mapping
- ✅ Extension fields for Tetragon-specific data

## Development

### Building
```bash
make build
```

### Testing
```bash
make test
```

### Configuration Testing
```bash
# Test with sample config
make run-config

# Validate output format
make validate-output
```

## Troubleshooting

### Common Issues

1. **Connection Failed**: Ensure Tetragon is running and accessible
   ```bash
   grpcurl -plaintext localhost:54321 tetragon.FineGuidanceSensors/GetEvents
   ```

2. **No Events Output**: Check Tetragon policies are loaded and generating events

3. **Invalid OCSF**: Validate against OCSF schema at https://schema.ocsf.io/

### Debugging
```bash
# Enable verbose logging
LOG_LEVEL=debug ./to_oscf

# Output raw Tetragon events for comparison  
tetra getevents -o json > tetragon-raw.json
```

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Ensure OCSF compliance
5. Submit pull request

## License

Apache License 2.0