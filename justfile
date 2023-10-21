set dotenv-load := false

_default:
    @just --list

docker_release $TAG:
  depot build --project v4z5w7md33 --platform linux/arm/v7,linux/arm64,linux/amd64 -t ghcr.io/erebe/wstunnel:$TAG -t ghcr.io/erebe/wstunnel:latest --push .

