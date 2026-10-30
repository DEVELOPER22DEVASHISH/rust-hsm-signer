# Dockerfile
# ---------- build ----------
FROM rust:1.97.1-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY tests ./tests
RUN cargo build --release --features loadtest --bins

# ---------- test ----------
FROM builder AS test
RUN apt-get update \
    && apt-get install -y --no-install-recommends softhsm2 \
    && rm -rf /var/lib/apt/lists/*
ENV PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
CMD ["cargo", "test", "--release"]

# ---------- runtime ----------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends softhsm2 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir -p /var/lib/softhsm/tokens /etc/softhsm \
    && printf '%s\n' \
    'directories.tokendir = /var/lib/softhsm/tokens' \
    'objectstore.backend = file' \
    'log.level = ERROR' \
    > /etc/softhsm/softhsm2.conf \
    && chmod 0755 /etc/softhsm \
    && chmod 0755 /var/lib/softhsm \
    && chmod 0755 /var/lib/softhsm/tokens \
    && chmod 0644 /etc/softhsm/softhsm2.conf \
    && chown -R app:app /var/lib/softhsm /etc/softhsm

COPY --from=builder /src/target/release/hsm-signer /usr/local/bin/hsm-signer
COPY --from=builder /src/target/release/loadtest   /usr/local/bin/loadtest
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
    && chmod 0755 /usr/local/bin/entrypoint.sh

ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf \
    PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so \
    HSM_TOKEN_LABEL=arkion \
    BIND_ADDR=0.0.0.0:8080 \
    METRICS_ADDR=0.0.0.0:9100

USER app
EXPOSE 8080
ENTRYPOINT ["/bin/sh", "/usr/local/bin/entrypoint.sh"]