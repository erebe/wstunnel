#!/bin/sh

# Ubuntu 18

sudo apt-get git llvm6.0-tools zlib1g-dev
export PATH="/usr/lib/llvm-6.0/bin/:$PATH"

wget https://github.com/commercialhaskell/stack/releases/download/v2.1.3/stack-2.1.3-linux-aarch64.tar.gz
tar xzvf stack-2.1.3-linux-aarch64.tar.gz
sudo cp stack-2.1.3-linux-aarch64/stack /usr/local/bin/
git clone https://github.com/erebe/wstunnel
cd wstunnel
stack setup
stack build
