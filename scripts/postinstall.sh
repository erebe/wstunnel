#!/bin/sh
# Post-installation script

set -e

# Reload systemd daemon to recognize new unit files
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

# Set proper permissions on config directory
if [ -d /etc/wstunnel ]; then
    chown root:wstunnel /etc/wstunnel
    chmod 750 /etc/wstunnel
fi

echo "wstunnel has been installed successfully!"
echo ""
echo "To get started:"
echo "  1. Place your configuration file in /etc/wstunnel/"
echo "  2. Start the service: systemctl start wstunnel-client@your-config"
echo "  3. Enable on boot: systemctl enable wstunnel-client@your-config"
echo ""
echo "Example configurations are available in /usr/share/doc/wstunnel/examples/"
echo "Documentation: /usr/share/doc/wstunnel/"
echo ""

exit 0
