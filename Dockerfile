FROM alpine:3.18 as builder

RUN apk --no-cache add ca-certificates git ghc curl musl-dev gmp-dev zlib-dev zlib-static pcre-dev xz make
RUN curl -sSL https://github.com/commercialhaskell/stack/releases/download/v2.11.1/stack-2.11.1-linux-$(uname -m)-static.tar.gz | tar xvz && \
    mv stack*/stack /usr/bin


COPY . /mnt
WORKDIR /mnt
RUN rm -rf ~/.stack &&  \
    stack config set system-ghc --global true && \
    echo '  ld-options: -static' >> wstunnel.cabal ; \
    stack install --no-install-ghc --system-ghc --ghc-options="-fPIC" --executable-stripping



FROM alpine:3.18 as final

COPY --from=builder  /root/.local/bin/wstunnel .

VOLUME /data
CMD cp wstunnel /data
