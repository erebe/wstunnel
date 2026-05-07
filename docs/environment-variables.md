# Environment Variable Reference

wstunnel supports configuration through environment variables with the prefix `WSTUNNEL_`.

## Format Rules

- **Prefix**: All environment variables must start with `WSTUNNEL_`
- **Separator**: Use double underscore `__` for nested fields
- **Case**: Environment variables are case-insensitive

## When to Use Environment Variables

Use environment variables when:
- Injecting deployment-specific overrides (log level, mode) on top of a shared config file
- Running in containers (Docker, Kubernetes) where mounting files is more work than env vars
- Passing secrets in CI/CD pipelines without writing them to disk

For complex structures like tunnel lists or headers, use config files instead — environment variables don't handle arrays cleanly.

## Priority Order

Configuration sources are loaded in this order (later overrides earlier):

1. Config file (if specified with `--config`)
2. Environment variables (`WSTUNNEL_*`)
3. CLI arguments (highest priority)

## Environment Variable Reference

### Global Settings
- `WSTUNNEL_MODE` — Mode selection: "client" or "server"
- `WSTUNNEL_LOG_LVL` — Log level: TRACE, DEBUG, INFO, WARN, ERROR, OFF
- `WSTUNNEL_NO_COLOR` — Disable colors: true/false

### Client Settings (selected examples)
- `WSTUNNEL_CLIENT__REMOTE_ADDR` — Server URL
- `WSTUNNEL_CLIENT__CONNECTION_MIN_IDLE` — Connection pool size
- `WSTUNNEL_CLIENT__TLS_VERIFY_CERTIFICATE` — Enable cert verification: true/false
- `WSTUNNEL_CLIENT__WEBSOCKET_PING_FREQUENCY` — Ping interval (e.g., "30s")

### Server Settings (selected examples)
- `WSTUNNEL_SERVER__REMOTE_ADDR` — Bind address
- `WSTUNNEL_SERVER__WEBSOCKET_PING_FREQUENCY` — Ping interval
- `WSTUNNEL_SERVER__RESTRICT_CONFIG` — Path to restrictions file

For the complete list of configurable fields, see [config-file.md](config-file.md).

## Global Options

```bash
# Set mode
export WSTUNNEL_MODE=client

# Set log level
export WSTUNNEL_LOG_LVL=DEBUG

# Disable colors
export WSTUNNEL_NO_COLOR=true
```

## Client Configuration

```bash
# Basic client setup
export WSTUNNEL_MODE=client
export WSTUNNEL_CLIENT__REMOTE_ADDR="wss://tunnel.example.com:443"

# Note: Complex types like arrays are better set in config files
# For tunnels, use config file or CLI arguments
```

## Server Configuration

```bash
# Basic server setup
export WSTUNNEL_MODE=server
export WSTUNNEL_SERVER__REMOTE_ADDR="ws://0.0.0.0:8080"
```

## Common Use Cases

### Override Log Level

```bash
# Start with config file but override log level via env var
export WSTUNNEL_LOG_LVL=TRACE
wstunnel --config config.yaml
```

### Docker/Container Deployments

```dockerfile
# Dockerfile
ENV WSTUNNEL_MODE=client
ENV WSTUNNEL_LOG_LVL=INFO
ENV WSTUNNEL_NO_COLOR=true

# Override at runtime
docker run -e WSTUNNEL_LOG_LVL=DEBUG myapp
```

### Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: wstunnel-env
data:
  WSTUNNEL_MODE: "client"
  WSTUNNEL_LOG_LVL: "INFO"
  WSTUNNEL_NO_COLOR: "false"
```

## Examples

### Example 1: Config File + Environment Override

**config.yaml:**
```yaml
mode: client
log_lvl: INFO

client:
  local_to_remote:
    - "tcp://8080:localhost:80"
  remote_addr: "ws://localhost:9090"
```

**Run with override:**
```bash
# Override log level to DEBUG
export WSTUNNEL_LOG_LVL=DEBUG
wstunnel --config config.yaml
```

### Example 2: Environment-Only Simple Config

For simple configurations, you can use environment variables alone:

```bash
export WSTUNNEL_MODE=server
export WSTUNNEL_LOG_LVL=INFO
export WSTUNNEL_SERVER__REMOTE_ADDR="ws://0.0.0.0:8080"

# Use with subcommand
wstunnel server
```

### Example 3: CLI Priority

```bash
# Config file has log_lvl: INFO
# Environment has LOG_LVL=DEBUG
export WSTUNNEL_LOG_LVL=DEBUG

# CLI overrides both (sets to WARN)
wstunnel --config config.yaml --log-lvl WARN
```

## Limitations

**Complex structures** (arrays, nested objects) are difficult to express as environment variables.
For these, use:
- Config files (YAML, TOML, JSON)
- CLI arguments

**Example of what to avoid:**
```bash
# This is hard to read and maintain
export WSTUNNEL_CLIENT__LOCAL_TO_REMOTE='["tcp://8080:localhost:80","tcp://8443:localhost:443"]'

# Better: Use config file for complex settings
```

## Best Practices

1. **Config File for Structure**: Use files for complex configurations (tunnels, headers, etc.)
2. **Environment for Overrides**: Use env vars to override simple values (log level, colors)
3. **CLI for Quick Tests**: Use CLI args for temporary overrides during testing
4. **Containers**: Use env vars for deployment-specific settings (log level, mode)
