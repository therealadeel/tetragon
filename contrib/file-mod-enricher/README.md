# File Mod Enricher

This tool demonstrates user-space post-processing of Tetragon events to add file hashes when monitored files are modified. It supports configurable file monitoring through a YAML configuration file.

## How it works

1. **Configurable Monitoring**: Loads target files from a YAML configuration
2. **Event Correlation**: Tracks `sys_openat` events that open target files with write permissions
3. **File Descriptor Tracking**: Maps file descriptors to the opened file  
4. **Hash Calculation**: When the corresponding `sys_close` event occurs, calculates SHA256 hash
5. **Change Detection**: Compares file metadata before and after to detect modifications
6. **Event Enrichment**: Outputs enriched events with file hash information

## Prerequisites

- Tetragon running with gRPC server enabled
- Apply the enhanced tracing policy: `example-tracingpolicy.yaml`

## Configuration

Create a `config.yaml` file to define which files to monitor:

```yaml
target_files:
  - "/etc/passwd"
  - "/etc/shadow"
  - "/etc/group"
  - "/etc/sudoers"
  - "/etc/hosts"
  - "/etc/ssh/sshd_config"
  - "/var/log/auth.log"

tetragon:
  server_address: "localhost:54321"

output:
  format: "json"
  indent: true
  include_metrics: false

tracker:
  cleanup_timeout: "5m"
  stats_interval: "1m"
```

## Environment Variables

- `TETRAGON_SERVER`: Tetragon gRPC server address (overrides config file)
- `ENRICHER_OUTPUT_FILE`: Explicit output file path for enriched events (default: stdout)
- `TETRAGON_EXPORT_DIR`: Directory where Tetragon exports files - enricher will create `tetragon-enriched.json` in same directory

## Usage

1. **Apply the tracing policy:**
   ```bash
   kubectl apply -f example-tracingpolicy.yaml
   ```

2. **Build and run the enricher:**
   ```bash
   go build -o file-mod-enricher
   
   # Run with default configuration (built-in file list)
   ./file-mod-enricher
   
   # Run with custom configuration file
   ./file-mod-enricher -config config.yaml
   
   # Run with output to file
   ENRICHER_OUTPUT_FILE=/tmp/enriched_events.json ./file-mod-enricher -config config.yaml
   
   # Run with output to same directory as Tetragon's export
   TETRAGON_EXPORT_DIR=/var/log/tetragon ./file-mod-enricher -config config.yaml
   # This creates: /var/log/tetragon/tetragon-enriched.json
   ```

3. **Test by modifying a monitored file:**
   ```bash
   # In another terminal
   echo "test:x:1001:1001:Test User:/home/test:/bin/bash" | sudo tee -a /etc/passwd
   ```

## Command Line Options

- `-config <path>`: Path to YAML configuration file (optional, uses defaults if not provided)

## Output Format

The enricher outputs JSON events with an additional `file_hash` field:

```json
{
  "process_kprobe": {
    "process": {
      "pid": {"value": 1234},
      "binary": "/usr/bin/tee"
    },
    "function_name": "sys_close",
    "args": [{"int_arg": 3}],
    "return": {"int_arg": 0}
  },
  "file_hash": {
    "algorithm": "sha256",
    "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "file_path": "/etc/passwd", 
    "timestamp": "2025-12-03T10:30:45.123456789Z",
    "file_size": 1156,
    "modification_time": "2025-12-03T10:30:45.123456789Z",
    "changed": true,
    "pre_file_info": {
      "size": 1024,
      "mod_time": "2025-12-03T10:29:00.000000000Z", 
      "permissions": "-rw-r--r--",
      "inode": 12345
    }
  },
  "time": "2025-12-03T10:30:45.123456789Z"
}
```

## Configuration Options

### Target Files
List any files you want to monitor for modifications. Examples:
- System files: `/etc/passwd`, `/etc/shadow`, `/etc/group`
- Configuration files: `/etc/ssh/sshd_config`, `/etc/sudoers`
- Log files: `/var/log/auth.log`, `/var/log/secure`
- Application configs: `/etc/nginx/nginx.conf`, `/etc/apache2/apache2.conf`

### Tetragon Settings
- `server_address`: gRPC endpoint for Tetragon (can be TCP or Unix socket)

### Output Settings
- `format`: Output format (`"json"` - only JSON currently supported)
- `indent`: Pretty-print JSON with indentation
- `include_metrics`: Include tracker statistics in each event

### Tracker Settings
- `cleanup_timeout`: How long to keep stale file descriptor tracking info
- `stats_interval`: How often to print statistics to logs

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────────┐
│   eBPF Events   │───▶│  Tetragon gRPC   │───▶│ File Mod                │
│ (sys_openat,    │    │     Server       │    │ Enricher Tool           │
│  sys_close)     │    │                  │    │                         │
└─────────────────┘    └──────────────────┘    │ • Configurable Targets  │
                                               │ • FD Tracking           │
                                               │ • Event Correlation     │
                                               │ • Hash Calculation      │
                                               │ • Change Detection      │
                                               │ • Event Enrichment      │
                                               └─────────────────────────┘
                                                          │
                                                          ▼
                                               ┌─────────────────────────┐
                                               │   Enriched Events       │
                                               │   with File Hashes      │
                                               │   and Change Detection  │
                                               └─────────────────────────┘
```

## Benefits of Configuration-Driven Approach

- **Flexibility**: Monitor any files without code changes
- **Security Focus**: Easily add new security-critical files
- **Environment Specific**: Different configs for dev/staging/prod
- **Performance**: Only monitor files you care about
- **Maintenance**: Update monitoring targets without rebuilding