FROM rust:1.86-bookworm AS build

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p tg_relay

FROM debian:bookworm AS mtproxy-build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential git libssl-dev zlib1g-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

RUN git clone --depth 1 https://github.com/TelegramMessenger/MTProxy /opt/MTProxy \
    && cd /opt/MTProxy \
    && make

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 zlib1g \
    && groupadd --system mtproxy \
    && useradd --system --gid mtproxy --home-dir /nonexistent --shell /usr/sbin/nologin mtproxy \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /app/target/release/tg_relay /usr/local/bin/tg_relay
COPY --from=mtproxy-build /opt/MTProxy/objs/bin/mtproto-proxy /opt/MTProxy/objs/bin/mtproto-proxy
COPY config/relay.example.toml /etc/tg-relay/config.toml

EXPOSE 443

ENTRYPOINT ["tg_relay"]
CMD ["--config", "/etc/tg-relay/config.toml"]
