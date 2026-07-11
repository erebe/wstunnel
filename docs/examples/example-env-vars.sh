#!/bin/bash
# Example: Running wstunnel with environment variables

# Set global options
export WSTUNNEL_MODE=client
export WSTUNNEL_LOG_LVL=DEBUG
export WSTUNNEL_NO_COLOR=false

# Set client configuration  
export WSTUNNEL_CLIENT__REMOTE_ADDR="ws://localhost:9090"

# Run wstunnel using config file (env vars will override file values)
wstunnel --config config.yaml

# Or run with subcommand
# wstunnel client
