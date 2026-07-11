#!/bin/sh
# Pre-installation script

set -e

# Create wstunnel user if it doesn't exist
if ! getent passwd wstunnel >/dev/null 2>&1; then
    useradd -r -s /bin/false -d /nonexistent -c "wstunnel service user" wstunnel
fi

# Create wstunnel group if it doesn't exist
if ! getent group wstunnel >/dev/null 2>&1; then
    groupadd -r wstunnel
fi

exit 0
