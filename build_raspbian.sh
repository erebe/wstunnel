#!/bin/sh

# Raspbian

sudo apt-get install git llvm-6.0-tools zlib1g-dev ghc
export PATH="/usr/lib/llvm-6.0/bin/:$PATH"

wget https://github.com/commercialhaskell/stack/releases/download/v2.1.3/stack-2.1.3-linux-arm.tar.gz
tar xzvf stack-*.tar.gz
sudo cp stack-*/stack /usr/local/bin/
git clone https://github.com/erebe/wstunnel
cd wstunnel

stack config set system-ghc --global true 
sed -i "s/resolver:.*/resolver: lts-12.26/g" stack.yaml
sed -i 's/-rtsopts ".*//g' wstunnel.cabal

stack setup
stack build
