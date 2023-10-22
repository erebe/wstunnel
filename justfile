set dotenv-load := false

_default:
    @just --list

make_release $VERSION:
   sed -ie 's/^version = .*/version = "'$VERSION'"/g' Cargo.toml
   cargo fmt --all -- --check --color=always || (echo "Use cargo fmt to format your code"; exit 1)
   cargo clippy --all --all-features -- -D warnings || (echo "Solve your clippy warnings to succeed"; exit 1)
   git add Cargo.*
   git commit -m 'Bump version v'$VERSION
   git tag v$VERSION -m 'version v'$VERSION
   git push
   git push --tags
   @just docker_release v$VERSION

docker_release $TAG:
  docker login -u erebe ghcr.io
  ~/.depot/bin/depot build --project v4z5w7md33 --platform linux/arm/v7,linux/arm64,linux/amd64 -t ghcr.io/erebe/wstunnel:$TAG -t ghcr.io/erebe/wstunnel:latest --push .

