FROM rust:1.91-bookworm AS builder
WORKDIR /app
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release && \
    strip target/release/pgwire-supabase-proxy

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/pgwire-supabase-proxy /usr/local/bin/pgwire-supabase-proxy
EXPOSE 5432
CMD ["pgwire-supabase-proxy"]
