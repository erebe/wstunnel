#!/bin/sh
# Pre-removal script

set -e

# Stop all running wstunnel services
if command -v systemctl >/dev/null 2>&1; then
    # Stop all client instances
    for service in $(systemctl list-units --all 'wstunnel-client@*' --no-legend | awk '{print $1}'); do
        systemctl stop "$service" >/dev/null 2>&1 || true
        systemctl disable "$service" >/dev/null 2>&1 || true
    done
    
    # Stop all server instances
    for service in $(systemctl list-units --all 'wstunnel-server@*' --no-legend | awk '{print $1}'); do
        systemctl stop "$service" >/dev/null 2>&1 || true
        systemctl disable "$service" >/dev/null 2>&1 || true
    done
fi

exit 0
