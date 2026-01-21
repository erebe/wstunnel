# Package Installation Scripts

These scripts are called automatically by the package manager (apt, yum/dnf) during install and removal. **Do not run them manually.**

## Why These Scripts Exist

Package managers need lifecycle hooks to:
- Create system users before files are installed (preinstall)
- Reload services and set permissions after install (postinstall)
- Stop running services before the binary is removed (preremove)

These scripts handle that lifecycle so wstunnel integrates cleanly with systemd on Debian- and RPM-based systems.

## Scripts

### preinstall.sh
**When:** Before package installation  
**Purpose:** Creates the `wstunnel` system user and group if they don't exist  
**Why:** The systemd units run as user `wstunnel`, so the user must exist before any files are placed on disk

### postinstall.sh
**When:** After package installation  
**Purpose:**
- Reloads systemd to recognize the new service unit files
- Sets ownership and permissions on `/etc/wstunnel` (owned by `root:wstunnel`, mode `750`)
- Prints a post-install message with next steps

### preremove.sh
**When:** Before package removal  
**Purpose:** Stops and disables all running wstunnel client and server instances  
**Why:** Prevents broken services and stale sockets when the binary is removed

## Package Contents

The `.deb` and `.rpm` packages include:

### Binary
- `/usr/bin/wstunnel` — Main binary

### Systemd Units
- `/usr/lib/systemd/system/wstunnel-client@.service` — Client service template
- `/usr/lib/systemd/system/wstunnel-server@.service` — Server service template

### Configuration
- `/etc/wstunnel/` — Configuration directory (created, owned by `root:wstunnel`)

### Documentation and Examples
- `/usr/share/doc/wstunnel/README.md`
- `/usr/share/doc/wstunnel/LICENSE`
- `/usr/share/doc/wstunnel/systemd-setup.md`
- `/usr/share/doc/wstunnel/config-file.md`
- `/usr/share/doc/wstunnel/examples/` — Configuration examples
  - `config-client-example.yaml`
  - `config-server-example.yaml`
  - `config.example.yaml`
  - `config.example.toml`
  - `restrictions.yaml`
  - `example-env-vars.sh`

## Building Packages

Packages are built automatically by goreleaser during the release process:

```bash
goreleaser release --snapshot --clean
```

Output: `.deb` and `.rpm` files in the `dist/` directory.
