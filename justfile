set dotenv-load := false

_default:
    @just --list

make_release $VERSION $FORCE="":
   sed -i 's/^version = .*/version = "'$VERSION'"/g' wstunnel-cli/Cargo.toml wstunnel/Cargo.toml
   cargo fmt --all -- --check --color=always || (echo "Use cargo fmt to format your code"; exit 1)
   #cargo clippy --all --all-features -- -D warnings || (echo "Solve your clippy warnings to succeed"; exit 1)
   git add wstunnel/Cargo.* wstunnel-cli/Cargo.* Cargo.*
   git commit -m 'Bump version v'$VERSION
   git tag $FORCE v$VERSION -m 'version v'$VERSION
   git push $FORCE
   git push $FORCE origin v$VERSION
   @just docker_release v$VERSION

docker_release $TAG:
  #docker login -u erebe ghcr.io
  #~/.depot/bin/depot build --project v4z5w7md33 --platform linux/arm/v7,linux/arm64,linux/amd64 -t ghcr.io/erebe/wstunnel:$TAG -t ghcr.io/erebe/wstunnel:latest --push .
  docker buildx create  --name builder  --driver=kubernetes --platform=linux/arm64   '--driver-opt="nodeselector=kubernetes.io/arch=arm64","tolerations=key=kubernetes.io/hostname,value=server","requests.cpu=16","requests.memory=16G"' --node=build-arm64
  docker buildx create --append --name builder  --driver=kubernetes --platform=linux/amd64   '--driver-opt="nodeselector=kubernetes.io/arch=amd64","tolerations=key=kubernetes.io/hostname,value=toybox","requests.cpu=16","requests.memory=16G"' --node=build-amd64
  docker buildx use builder
  docker buildx build \
    --platform linux/arm/v7,linux/arm64,linux/amd64 \
    --cache-from type=registry,ref=ghcr.io/erebe/wstunnel:cache \
    --cache-to type=registry,mode=max,image-manifest=true,oci-mediatypes=true,ref=ghcr.io/erebe/wstunnel:cache \
    -t ghcr.io/erebe/wstunnel:$TAG \
    -t ghcr.io/erebe/wstunnel:latest \
    --push .
  docker buildx rm builder

test:
   cargo nextest run --all-features

bump_deps:
  cargo upgrade  --recursive true --incompatible allow
  cargo update --recursive

linter_fix:
   cargo clippy --fix  --all-features --locked --allow-dirty
