ARG BUILDER_IMAGE=builder_cache
ARG ALPINE_IMAGE_TAG=3.18

############################################################
# Cache image with all the deps
FROM rust:1.73-alpine${ALPINE_IMAGE_TAG} AS builder_cache

RUN apk add musl-dev
RUN rustup component add rustfmt clippy

WORKDIR /build
COPY . ./


RUN cargo fmt --all -- --check --color=always || (echo "Use cargo fmt to format your code"; exit 1)
RUN cargo clippy --all --all-features -- -D warnings || (echo "Solve your clippy warnings to succeed"; exit 1)

#RUN cargo test --all --all-features
#RUN just test "tcp://localhost:2375" || (echo "Test are failing"; exit 1)

#ENV RUSTFLAGS="-C link-arg=-Wl,--compress-debug-sections=zlib -C force-frame-pointers=yes"
RUN cargo build --tests --all-features
#RUN cargo build --release --all-features


############################################################
# Builder for production image
FROM ${BUILDER_IMAGE} AS builder_release

WORKDIR /build
COPY . ./

ARG BIN_TARGET=--bins
ARG PROFILE=release

#ENV RUSTFLAGS="-C link-arg=-Wl,--compress-debug-sections=zlib -C force-frame-pointers=yes"
RUN cargo build --profile=${PROFILE} ${BIN_TARGET}


############################################################
# Final image
FROM alpine:${ALPINE_IMAGE_TAG} as final-image

RUN apk add dumb-init && \
  adduser -Ds /bin/sh app

WORKDIR /home/app

ARG PROFILE=release
COPY --from=builder_release  /build/target/${PROFILE}/wstunnel wstunnel

ENV RUST_LOG="INFO"
ENV SERVER_PROTOCOL="wss"
ENV SERVER_LISTEN="[::]"
ENV SERVER_PORT="8080"
EXPOSE 8080

USER app

ENTRYPOINT ["/usr/bin/dumb-init", "-v", "--"]
CMD ["/bin/sh", "-c", "exec /home/app/wstunnel server ${SERVER_PROTOCOL}://${SERVER_LISTEN}:${SERVER_PORT}"]
