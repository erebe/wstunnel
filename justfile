set dotenv-load := false

_default:
    @just --list

docker_build:
  depot build --project v4z5w7md33 --platform linux/arm/v7,linux/arm64,linux/amd64 -t ghcr.io/erebe/wstunnel:v7.0.0 -t ghcr.io/erebe/wstunnel:latest --push .

