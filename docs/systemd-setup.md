# How to Run wstunnel as a systemd Service

This guide shows how to run wstunnel as a system service with automatic restarts and centralized logging.

## Prerequisites

- A systemd-based Linux distribution (Debian, Ubuntu, Fedora, RHEL, Arch, etc.)
- Root or sudo access
- wstunnel installed (via `.deb`/`.rpm` package, or binary placed manually)

## Installation

### If you installed via .deb or .rpm package

The systemd unit files, wstunnel user, and `/etc/wstunnel/` directory are set up automatically by the package scripts. Skip to [Configuration](#configuration).

### If you installed manually

1. Copy the systemd unit files to the systemd directory:
```bash
sudo cp wstunnel-client@.service /etc/systemd/system/
sudo cp wstunnel-server@.service /etc/systemd/system/
```

2. Create the wstunnel user and group:
```bash
sudo useradd -r -s /bin/false wstunnel
```

3. Create directories for configuration and logs:
```bash
sudo mkdir -p /etc/wstunnel
sudo mkdir -p /var/log/wstunnel
sudo chown wstunnel:wstunnel /var/log/wstunnel
```

4. Place your configuration files in `/etc/wstunnel/`:
```bash
sudo cp config-client-example.yaml /etc/wstunnel/my-tunnel.yaml
sudo chown root:wstunnel /etc/wstunnel/my-tunnel.yaml
sudo chmod 640 /etc/wstunnel/my-tunnel.yaml
```

## Configuration

Place a wstunnel config file in `/etc/wstunnel/` named after the instance you want to run. The file name (without the `.yaml` extension) becomes the instance name used in `systemctl` commands.

## Usage

The service uses instance naming (the `@` symbol), where the instance name corresponds to the config file name (without the `.yaml` extension).

### Start a client
If you have `/etc/wstunnel/my-tunnel.yaml`:
```bash
sudo systemctl start wstunnel-client@my-tunnel
```

### Enable auto-start on boot
```bash
sudo systemctl enable wstunnel-client@my-tunnel
```

### Check status
```bash
sudo systemctl status wstunnel-client@my-tunnel
```

### View logs
```bash
sudo journalctl -u wstunnel-client@my-tunnel -f
```

### Multiple tunnels
You can run multiple instances with different configs:
```bash
# Start multiple clients
sudo systemctl start wstunnel-client@tunnel1
sudo systemctl start wstunnel-client@tunnel2

# Start a server
sudo systemctl start wstunnel-server@server-config
```

## Security Notes

The systemd units include security hardening options:
- Runs as unprivileged `wstunnel` user
- Restricted filesystem access
- Limited system calls
- Memory execution protection
- Network namespace restrictions

If you need to bind to privileged ports (< 1024), consider using:
- `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the service file
- Or use port forwarding/proxy (recommended)

## Troubleshooting

### Service fails to start

Check logs for the specific error:
```bash
journalctl -u wstunnel-client@my-tunnel -n 50
```

Common causes:

- **Permission denied on `/etc/wstunnel/`**: Fix ownership and permissions:
  ```bash
  sudo chown root:wstunnel /etc/wstunnel
  sudo chmod 750 /etc/wstunnel
  ```
- **Config file not found**: Ensure `/etc/wstunnel/my-tunnel.yaml` exists and is readable by the `wstunnel` group
- **Binary not found**: Package installs place the binary at `/usr/bin/wstunnel`; if you installed manually to `/usr/local/bin/`, edit the `ExecStart=` line in the service file to match

### Check binary path

```bash
which wstunnel
systemctl cat wstunnel-client@my-tunnel | grep ExecStart
```
