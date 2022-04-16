# Build Cache image
FROM fpco/stack-build-small:lts-19.2 as builder-cache

COPY stack.yaml /mnt
COPY *.cabal /mnt
WORKDIR /mnt
RUN rm -rf ~/.stack &&  \
    stack config set system-ghc --global true && \
    stack setup && \
    stack install --ghc-options="-fPIC" --only-dependencies



# Build phase
FROM builder-cache as builder
# FROM ghcr.io/erebe/wstunnel:build-cache as builder
COPY . /mnt

RUN echo '  ld-options: -static' >> wstunnel.cabal ; \
    stack install --ghc-options="-fPIC"
#RUN upx /root/.local/bin/wstunnel



# Final Image
FROM alpine:latest as runner

LABEL org.opencontainers.image.source https://github.com/erebe/server

COPY --from=builder /root/.local/bin/wstunnel /
RUN adduser -D abc && chmod +x /wstunnel

USER abc
WORKDIR /

CMD ["/wstunnel"]

