# Build the Rust binary statically against musl.
FROM rust:1-alpine AS builder
RUN apk add --no-cache musl-dev pkgconfig
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

# Runtime image: only the binary.
FROM alpine:3
WORKDIR /app
COPY --from=builder /build/target/release/mailcow-ldap-sync /app/mailcow-ldap-sync

VOLUME [ "/app/db" ]
CMD ["/app/mailcow-ldap-sync"]
