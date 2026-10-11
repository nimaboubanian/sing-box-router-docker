#!/usr/bin/env bash
# entrypoint.sh — fetch+validate rule-sets, render sing-box config from env vars, run sing-box.
# Subcommands (all network-free except the run path):
#   render            print the rendered config to stdout
#   mirror-url <url>  print the CDN mirror of a rule-set URL
#   fetch-rulesets    download+validate every rule-set into $RULESET_DIR
set -euo pipefail

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

REJECT_RULESET_URLS_DEFAULT='https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ads-all.srs,https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-malware.srs,https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-phishing.srs,https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cryptominers.srs'
DIRECT_DOMAIN_RULESET_URLS_DEFAULT='https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs'
DIRECT_IP_RULESET_URLS_DEFAULT='https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs'

RULESET_DIR="${RULESET_DIR:-/var/lib/sing-box/rulesets}"
SEED_DIR="${SEED_DIR:-/usr/local/share/sing-box/rulesets}"
ALL_RULESET_URLS="${REJECT_RULESET_URLS-$REJECT_RULESET_URLS_DEFAULT},${DIRECT_DOMAIN_RULESET_URLS-$DIRECT_DOMAIN_RULESET_URLS_DEFAULT},${DIRECT_IP_RULESET_URLS-$DIRECT_IP_RULESET_URLS_DEFAULT}"

tag_of() { printf '%s' "$1" | jq -Rr 'sub(".*[/@]"; "") | sub("\\.srs$"; "")'; }

mirror_url() {
    printf '%s' "$1" | jq -Rr '
        sub("^https://raw\\.githubusercontent\\.com/"; "https://cdn.jsdelivr.net/gh/")
        | sub("/rule-set/"; "@rule-set/")'
}

render_config() {
    jq -n \
        --arg rd "$RULESET_DIR" \
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
        def rtag: sub(".*[/@]"; "") | sub("\\.srs$"; "");
        # Rule-sets live on disk: the entrypoint fetched+validated them before
        # sing-box starts, so boot needs no network and no cache.db priming.
        def rset: {
            type: "local",
            tag: rtag,
            format: "binary", path: ($rd + "/" + rtag + ".srs")
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

# Candidate sources for one rule-set: the URL itself, its CDN mirror, then any
# RULESET_MIRRORS entries ("@file@" is replaced with the URL basename).
rule_set_sources() {
    printf '%s\n' "$1"
    local mirror base tpl
    mirror="$(mirror_url "$1")"
    [[ "$mirror" == "$1" ]] || printf '%s\n' "$mirror"
    base="${1##*/}"
    while IFS= read -r tpl; do
        [[ -n "$tpl" ]] && printf '%s\n' "${tpl//@file@/$base}"
    done < <(printf '%s\n' "${RULESET_MIRRORS-}" | tr ',' '\n')
}

# 0 = parses as a sing-box rule-set. decompile is the parse gate on sing-box
# >= 1.11; without it, fall back to a non-empty file.
PARSE_CMD=()
valid_rule_set() {
    [[ -s "$1" ]] || return 1
    if ((${#PARSE_CMD[@]})); then
        sing-box "${PARSE_CMD[@]}" "$1" -o /dev/null >/dev/null 2>&1
    fi
}

# 0 = a usable file landed at $RULESET_DIR/<tag>.srs. A rule-set already on
# disk — or baked into the image — counts as usable, so a boot never depends on
# the network. Only tags with no seed and no cached copy go out to the network.
fetch_rule_set() {
    local url="$1" tag dest seed src
    tag="$(tag_of "$url")"
    dest="$RULESET_DIR/$tag.srs"
    seed="$SEED_DIR/$tag.srs"
    if valid_rule_set "$dest"; then
        log "ruleset $tag: reusing $(wc -c <"$dest") bytes already on disk"
        return 0
    fi
    if valid_rule_set "$seed"; then
        log "ruleset $tag: seeding $(wc -c <"$seed") bytes from image"
        if cp "$seed" "$dest" && valid_rule_set "$dest"; then
            return 0
        fi
        log "ruleset $tag: seed unusable after copy, falling back to fetch"
        rm -f "$dest"
    fi
    rm -f "$dest"
    while IFS= read -r src; do
        log "ruleset $tag: fetching $src"
        if curl -fsSL --retry 3 --retry-all-errors --max-time 30 \
               -o "$dest.part" "$src" && valid_rule_set "$dest.part"; then
            mv "$dest.part" "$dest"
            log "ruleset $tag: ok ($(wc -c <"$dest") bytes)"
            return 0
        fi
        rm -f "$dest.part"
        log "ruleset $tag: source unusable (fetch failed or invalid): $src"
    done < <(rule_set_sources "$url")
    log "FATAL: rule-set $tag could not be fetched from any source"
    return 1
}

fetch_rule_sets() {
    local -a urls=()
    mapfile -t urls < <(jq -Rrn --arg csv "$ALL_RULESET_URLS" '
        $csv | split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0)) | .[]')
    ((${#urls[@]})) || { log "no rule-sets configured, skipping fetch"; return 0; }
    if [[ "$(sing-box rule-set --help 2>&1)" == *decompile* ]]; then
        PARSE_CMD=(rule-set decompile)
    fi
    mkdir -p "$RULESET_DIR"
    log "resolving ${#urls[@]} rule-set(s) into $RULESET_DIR (seed: $SEED_DIR)"
    local url failed=0
    for url in "${urls[@]}"; do
        fetch_rule_set "$url" || failed=$((failed + 1))
    done
    # A missing rule-set means the rendered config points at a file that isn't
    # there, so sing-box would refuse to start anyway. Fail loudly and let
    # compose's backoff retry instead of running with degraded routing.
    if ((failed)); then
        log "FATAL: $failed of ${#urls[@]} rule-set(s) unavailable"
        return 1
    fi
    log "all ${#urls[@]} rule-set(s) fetched and validated"
}

case "${1:-}" in
    render)       render_config; exit 0 ;;
    mirror-url)   mirror_url "${2:?usage: entrypoint.sh mirror-url <url>}"; echo; exit 0 ;;
    fetch-rulesets) fetch_rule_sets || exit 1; exit 0 ;;
esac

CONFIG_DIR="/etc/sing-box"
mkdir -p "$CONFIG_DIR" /var/lib/sing-box

log "fetching rule-sets"
fetch_rule_sets

log "rendering config"
render_config > "$CONFIG_DIR/config.json"

log "validating config"
sing-box check -c "$CONFIG_DIR/config.json"

log "starting sing-box"
exec sing-box run -c "$CONFIG_DIR/config.json"
