ARG BASE_IMAGE=docker.io/library/alpine:3.20
FROM ${BASE_IMAGE}

ARG SINGBOX_VERSION=1.14.2
ARG TARGETARCH=amd64

RUN apk add --no-cache bash curl jq tini ca-certificates

RUN set -eux; \
    curl -fsSL -o /tmp/sing-box.tar.gz \
        "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}-musl.tar.gz"; \
    tar -xzf /tmp/sing-box.tar.gz -C /tmp \
        "sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}-musl/sing-box"; \
    mv "/tmp/sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}-musl/sing-box" /usr/local/bin/sing-box; \
    chmod +x /usr/local/bin/sing-box; \
    rm -rf /tmp/sing-box.tar.gz "/tmp/sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}-musl"; \
    sing-box version

COPY --chmod=755 scripts /usr/local/bin

# Bake the rule-sets in so the container boots with no network at all. Same
# fetch path the entrypoint uses (retry -> jsDelivr mirror -> validate).
# SEED is a cache-buster, not data: without it the GHA cache reuses this layer
# forever and the scheduled rebuild ships the same stale rule-sets.
ARG SEED=""
RUN : "$SEED" && RULESET_DIR=/usr/local/share/sing-box/rulesets entrypoint.sh fetch-rulesets

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
