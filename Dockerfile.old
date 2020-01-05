FROM nixos/nix as builder
MAINTAINER github@erebe.eu

RUN nix-channel --add https://nixos.org/channels/nixpkgs-unstable nixpkgs
RUN nix-channel --update
RUN nix-env -i bash upx

WORKDIR /mnt
COPY stack.yaml /mnt
COPY *.cabal /mnt
COPY default.nix /mnt

RUN nix-build --no-link -A fullBuildScript
COPY . /mnt
RUN $(nix-build --no-link -A fullBuildScript)
