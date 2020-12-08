# Build Cache image
FROM alpine:3.12 as builder-cache

RUN apk --no-cache add ca-certificates git ghc curl musl-dev gmp-dev zlib-dev zlib-static pcre-dev xz make upx
RUN curl -sSL https://github.com/commercialhaskell/stack/releases/download/v2.1.3/stack-2.1.3-linux-x86_64-static.tar.gz | tar xvz && \
    mv stack*/stack /usr/bin


COPY stack.yaml /mnt
COPY *.cabal /mnt
WORKDIR /mnt
RUN sed -i 's/lts-16.25/lts-16.4/' stack.yaml && \
    rm -rf ~/.stack &&  \
    stack config set system-ghc --global true && \
    stack setup && \
    stack install --split-objs --ghc-options="-fPIC" --only-dependencies



# Build phase
#FROM builder-cache as builder
FROM ghcr.io/erebe/wstunnel:build-cache as builder
COPY . /mnt

RUN sed -i 's/lts-16.25/lts-16.4/' stack.yaml 
RUN echo '  ld-options: -static' >> wstunnel.cabal ; \
    stack install --split-objs --ghc-options="-fPIC"
#RUN upx /root/.local/bin/wstunnel



# Final Image
FROM alpine:latest as runner

LABEL org.opencontainers.image.source https://github.com/erebe/server

COPY --from=builder /root/.local/bin/wstunnel /
RUN adduser -D abc && chmod +x /wstunnel

USER abc
WORKDIR /

CMD ["/wstunnel"]

