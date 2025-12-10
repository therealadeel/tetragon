# Log Rotation Support

The Tetragon Control Plane Client supports log rotation via SIGHUP signal handling, making it compatible with standard Linux log rotation tools like `logrotate`.

## How It Works

1. **File Logging**: The client writes logs to files in a configurable directory
2. **SIGHUP Handling**: When the process receives a SIGHUP signal, it:
   - Closes the current log file handle
   - Reopens the log file (creating a new one if it was rotated)
   - Continues logging to the new file

## Configuration

### Application Configuration

In your `config.yaml`:

```yaml
logging:
  level: "info"
  format: "json"  # or "text"
  output_directory: "/var/log/tetragon"
```

### Log Files Created

- **JSON format**: `/var/log/tetragon/tetragon-control-plane.json`
- **Text format**: `/var/log/tetragon/tetragon-control-plane.log`

### Command-Line Overrides

```bash
./control-plane-client \
  --config config.yaml \
  --log-level debug \
  --log-format json \
  --log-output-directory /var/log/tetragon
```

## Logrotate Integration

### Setup

1. Copy the logrotate configuration:
   ```bash
   sudo cp logrotate-example.conf /etc/logrotate.d/tetragon-control-plane
   ```

2. Adjust the configuration if needed (see below)

3. Test the configuration:
   ```bash
   sudo logrotate -d /etc/logrotate.d/tetragon-control-plane
   ```

4. Force a rotation to verify:
   ```bash
   sudo logrotate -f /etc/logrotate.d/tetragon-control-plane
   ```

### Logrotate Configuration

Example configuration (`/etc/logrotate.d/tetragon-control-plane`):

```
/var/log/tetragon/tetragon-control-plane.log /var/log/tetragon/tetragon-control-plane.json {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    postrotate
        pkill -HUP -f "control-plane-client" || true
    endscript
}
```

### Configuration Options

- **daily/weekly/monthly**: Rotation frequency
- **rotate N**: Keep N rotated log files
- **compress**: Compress old log files with gzip
- **delaycompress**: Don't compress the most recent rotated file (in case process still writing)
- **missingok**: Don't error if log file doesn't exist
- **notifempty**: Don't rotate empty log files
- **create MODE OWNER GROUP**: Permissions for new log file after rotation
- **postrotate**: Commands to run after rotation (sends SIGHUP to reopen files)

### Alternative: systemd Service

If running as a systemd service, you can reload with:

```
postrotate
    systemctl reload tetragon-control-plane.service || true
endscript
```

And in your systemd unit file:

```ini
[Service]
ExecReload=/bin/kill -HUP $MAINPID
```

## Manual Log Rotation

You can manually trigger log rotation:

```bash
# 1. Move the current log file
sudo mv /var/log/tetragon/tetragon-control-plane.log \
        /var/log/tetragon/tetragon-control-plane.log.1

# 2. Send SIGHUP to reopen files
sudo pkill -HUP -f "control-plane-client"

# 3. Compress the old log
sudo gzip /var/log/tetragon/tetragon-control-plane.log.1
```

## Verification

After rotation, verify the client reopened the log file:

```bash
# Check the log file shows reopening message
sudo grep "log files reopened successfully" /var/log/tetragon/tetragon-control-plane.log

# Check the client is writing to the new file
sudo tail -f /var/log/tetragon/tetragon-control-plane.log

# Verify old logs are rotated
ls -lh /var/log/tetragon/
```

## Troubleshooting

### Logs still going to old file after rotation

**Problem**: Process didn't receive SIGHUP or has wrong PID

**Solution**:
```bash
# Find the actual PID
ps aux | grep control-plane-client

# Send SIGHUP manually
kill -HUP <PID>

# Check process name in logrotate config matches
pgrep -a control-plane-client
```

### Permission denied errors

**Problem**: Process doesn't have permission to create new log file

**Solution**:
```bash
# Ensure log directory has correct permissions
sudo chown -R <user>:<group> /var/log/tetragon
sudo chmod 755 /var/log/tetragon

# Or run as root if needed
```

### Multiple processes receiving SIGHUP

**Problem**: `pkill -HUP -f "control-plane-client"` matches multiple processes

**Solution**: Use PID file or more specific pattern:
```bash
# In postrotate:
pkill -HUP -f "^/usr/local/bin/control-plane-client" || true

# Or use PID file:
kill -HUP $(cat /var/run/control-plane-client.pid) || true
```

## Logging to stdout (disable file logging)

To disable file logging and log to stdout instead:

```yaml
logging:
  level: "info"
  format: "json"
  output_directory: ""  # Empty = stdout
```

Or via command-line:
```bash
./control-plane-client --config config.yaml --log-output-directory ""
```

## See Also

- [logrotate(8)](https://linux.die.net/man/8/logrotate)
- [logrotate.conf(5)](https://linux.die.net/man/5/logrotate.conf)
