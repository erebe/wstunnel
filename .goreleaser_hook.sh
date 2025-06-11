#!/usr/bin/env bash

set -x

go_arch=$1
go_os=$2
go_arm=$3
project_name=$4

# Make Go -> Rust arch/os mapping
case $go_arch in
    amd64) rust_arch='x86_64' ;;
    arm64) rust_arch='aarch64' ;;
    arm) case $go_arm in
           6) rust_arch="arm-" ;;
           7) rust_arch='armv7-' ;;
         esac
    ;;
    386) rust_arch='i686' ;;
    *) echo "unknown arch: $go_arch" && exit 1 ;;
esac
case $go_os in
    linux) rust_os='linux-musl' ;;
    darwin) rust_os='apple-darwin' ;;
    windows) rust_os='windows' ;;
    freebsd) rust_os='freebsd' ;;
    android) rust_os='android' ;;
    *) echo "unknown os: $go_os" && exit 1 ;;
esac

# Find artifacts and uncompress in the corresponding directory
if [ -z "$go_arm" ]
then 
  DIST_DIR=$(find dist -type d -name "*${go_os}_${go_arch}*")
else
  DIST_DIR=$(find dist -type d -name "*${go_os}_${go_arch}_${go_arm}*")
fi

echo "DIST_DIR: $DIST_DIR"
rm -f ${DIST_DIR}/${project_name}*

find artifacts -type f -wholename "*${rust_arch}*${rust_os}*/${project_name}*" -exec cp {} ${DIST_DIR}/ \;

