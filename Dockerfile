FROM alpine:3.11 as builder
MAINTAINER github@erebe.eu

RUN apk --no-cache add ca-certificates git ghc curl musl-dev gmp-dev zlib-dev zlib-static pcre-dev xz make upx
RUN curl -sSL https://github.com/commercialhaskell/stack/releases/download/v2.1.3/stack-2.1.3-linux-x86_64-static.tar.gz | tar xvz && \
    mv stack*/stack /usr/bin


COPY stack.yaml /mnt
COPY *.cabal /mnt
WORKDIR /mnt
RUN rm -rf ~/.stack &&  \
    stack config set system-ghc --global true && \
    stack setup && \
    stack install --split-objs --ghc-options="-fPIC" --only-dependencies

COPY . /mnt

RUN echo '  ld-options: -static' >> wstunnel.cabal ; \
    stack install --split-objs --ghc-options="-fPIC"
#RUN upx /root/.local/bin/wstunnel



FROM alpine:latest as runner
MAINTAINER github@erebe.eu

WORKDIR /root
COPY --from=builder /root/.local/bin/wstunnel .
RUN chmod +x ./wstunnel

CMD ["./wstunnel"]

