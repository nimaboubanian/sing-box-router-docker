#!/usr/bin/env bash
# entrypoint.sh — render sing-box config from env vars, validate, run sing-box.
# `entrypoint.sh render` prints the rendered config to stdout (no network).
set -euo pipefail

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

REJECT_RULESET_URLS_DEFAULT='https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ads-all.srs,https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-malware.srs,https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-phishing.srs,https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cryptominers.srs'
DIRECT_DOMAIN_RULESET_URLS_DEFAULT='https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs'
DIRECT_IP_RULESET_URLS_DEFAULT='https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs'

render_config() {
    jq -n \
        --arg listen_port "${LISTEN_PORT:-1070}" \
        --arg proxy_host "${PROXY_HOST:-lb}" \
        --arg proxy_port "${PROXY_PORT:-1081}" \
        --arg reject_urls "${REJECT_RULESET_URLS-$REJECT_RULESET_URLS_DEFAULT}" \
        --arg ddomain_urls "${DIRECT_DOMAIN_RULESET_URLS-$DIRECT_DOMAIN_RULESET_URLS_DEFAULT}" \
        --arg dip_urls "${DIRECT_IP_RULESET_URLS-$DIRECT_IP_RULESET_URLS_DEFAULT}" \
        --arg doh "${DOH_SERVER:-1.1.1.1}" \
        --arg lvl "${LOG_LEVEL:-warn}" \
        --arg extra_domains "${EXTRA_DIRECT_DOMAINS-}" \
        --arg extra_ips "${EXTRA_DIRECT_IPS-}" \
        --arg xrej_d "${EXTRA_REJECT_DOMAINS-}" \
        --arg xrej_i "${EXTRA_REJECT_IPS-}" \
        --arg xprox_d "${EXTRA_PROXY_DOMAINS-}" \
        --arg xprox_i "${EXTRA_PROXY_IPS-}" \
        '
        def urls: split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0));
        def rset: {
            type: "remote",
            tag: (. | sub(".*[/@]"; "") | sub("\\.srs$"; "")),
            format: "binary", url: .
        };
        # extra(raw_csv; match_key; effect) — raw destinations -> one route rule.
        # effect is {action:"reject"} or {outbound:"direct-out"/"proxy-out"}.
        # Rule order below fixes priority: reject > proxy > direct.
        def extra($vals; $match; $effect):
            if ($vals | urls | length) > 0
            then [{($match): ($vals | urls)} + $effect]
            else [] end;
        ($reject_urls | urls | map(rset)) as $ru
        | ($ddomain_urls | urls | map(rset)) as $du
        | ($dip_urls | urls | map(rset)) as $iu
        | {
            log: {level: $lvl},
            http_clients: [{tag: "dl-via-proxy", detour: "proxy-out"}],
            dns: {servers: [
                {type: "local", tag: "dns-local"},
                {type: "https", tag: "doh", server: $doh, detour: "proxy-out"}
            ]},
            inbounds: [{
                type: "mixed", tag: "mixed-in",
                listen: "::", listen_port: ($listen_port | tonumber)
            }],
            outbounds: [
                {type: "direct", tag: "direct-out"},
                {type: "socks", tag: "proxy-out",
                 server: $proxy_host, server_port: ($proxy_port | tonumber)}
            ],
            route: {
                default_domain_resolver: "dns-local",
                default_http_client: "dl-via-proxy",
                rules: (
                    [{action: "sniff"}]
                    + (if ($ru | length) > 0
                       then [{rule_set: [$ru[].tag], action: "reject"}] else [] end)
                    + extra($xrej_d; "domain_suffix"; {action: "reject"})
                    + extra($xprox_d; "domain_suffix"; {outbound: "proxy-out"})
                    + extra($xrej_i; "ip_cidr"; {action: "reject"})
                    + extra($xprox_i; "ip_cidr"; {outbound: "proxy-out"})
                    + [{ip_is_private: true, outbound: "direct-out"}]
                    + (if ($du | length) > 0
                       then [{rule_set: [$du[].tag], outbound: "direct-out"}] else [] end)
                    + extra($extra_domains; "domain_suffix"; {outbound: "direct-out"})
                    + [{action: "resolve", server: "doh"}]
                    # IP extras repeated post-resolve: bare ip rules before resolve
                    # are only seen by IP-connecting clients; domain-connected clients
                    # are re-matched here (reject/proxy still override geoip-ir).
                    + extra($xrej_i; "ip_cidr"; {action: "reject"})
                    + extra($xprox_i; "ip_cidr"; {outbound: "proxy-out"})
                    + (if ($iu | length) > 0
                       then [{rule_set: [$iu[].tag], outbound: "direct-out"}] else [] end)
                    + extra($extra_ips; "ip_cidr"; {outbound: "direct-out"})
                ),
                rule_set: ($ru + $du + $iu),
                final: "proxy-out"
            },
            experimental: {
                cache_file: {enabled: true, path: "/var/lib/sing-box/cache.db"}
            }
        }'
}

if [[ "${1:-}" == "render" ]]; then
    render_config
    exit 0
fi

CONFIG_DIR="/etc/sing-box"
mkdir -p "$CONFIG_DIR" /var/lib/sing-box

log "rendering config"
render_config > "$CONFIG_DIR/config.json"

log "validating config"
sing-box check -c "$CONFIG_DIR/config.json"

log "starting sing-box"
exec sing-box run -c "$CONFIG_DIR/config.json"
