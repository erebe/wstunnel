#!/usr/bin/env bash

go_arch=$1
go_os=$2
project_name=$3

# Make Go -> Rust arch/os mapping
case $go_arch in
    amd64) rust_arch='x86_64' ;;
    arm64) rust_arch='aarch64' ;;
    *) echo "unknown arch: $go_arch" && exit 1 ;;
esac
case $go_os in
    linux) rust_os='linux' ;;
    darwin) rust_os='apple-darwin' ;;
    windows) rust_os='windows' ;;
    *) echo "unknown os: $go_os" && exit 1 ;;
esac

# Find artifacts and uncompress in the corresponding directory
find artifacts -type f -name "*${rust_arch}*${rust_os}*" -exec unzip -d dist/${project_name}_${go_os}_${go_arch} {} \;

