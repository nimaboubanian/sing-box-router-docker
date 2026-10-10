#!/usr/bin/env bash
# test-render.sh — contract tests for `entrypoint.sh render`, run inside the image.
# Usage: ./build.sh && scripts/test-render.sh   (image must contain the scripts)
set -euo pipefail

IMG="${IMAGE:-sing-box-router:latest}"
fail=0

render() { # render [KEY=VAL ...] -> rendered config JSON on stdout (exit status ignored)
    local envs=()
    local kv
    for kv in "$@"; do envs+=(-e "$kv"); done
    docker run --rm "${envs[@]}" --entrypoint /usr/local/bin/entrypoint.sh "$IMG" render || true
}

assert() { # name json jq-filter
    local name="$1" json="$2" filter="$3"
    if printf '%s' "$json" | jq -e "$filter" >/dev/null 2>&1; then
        echo "$name: PASS"
    else
        echo "$name: FAIL"
        printf '%s' "$json" | jq -e "$filter" >/dev/null 2>&1 || \
            printf '%s' "$json" | jq "$filter" >&2 || true
        fail=1
    fi
}

# Case 1: defaults — full structure and rule order
out="$(render)"
assert "case1 defaults" "$out" '
    .inbounds[0].listen_port == 1070
    and (.outbounds | map(.tag)) == ["direct-out", "proxy-out"]
    and (.outbounds[] | select(.tag == "proxy-out") | .server == "lb" and .server_port == 1081)
    and .dns.servers[0] == {type: "local", tag: "dns-local"}
    and .dns.servers[1] == {type: "https", tag: "doh", server: "1.1.1.1", detour: "proxy-out"}
    and .route.default_domain_resolver == "dns-local"
    and .route.final == "proxy-out"
    and (.route.rules | map(.action // .outbound)) == ["sniff", "reject", "direct-out", "direct-out", "resolve", "direct-out"]
    and .route.rules[2].ip_is_private == true
    and .route.rules[1].rule_set == ["geosite-category-ads-all", "geosite-malware", "geosite-phishing", "geosite-cryptominers"]
    and (.route.rule_set | length) == 6
    and all(.route.rule_set[]; .format == "binary")
    and (.route.rule_set | map(has("download_detour")) | any | not)
    and .http_clients == [{tag: "dl-via-proxy", detour: "proxy-out"}]
    and .route.default_http_client == "dl-via-proxy"
'

# Case 2: empty DIRECT_IP_RULESET_URLS — omit rule and rule_sets, keep resolve
out="$(render DIRECT_IP_RULESET_URLS=)"
assert "case2 empty ip list" "$out" '
    (.route.rule_set | length) == 5
    and ([.route.rules[] | .outbound // empty | select(. == "direct-out")] | length) == 2
    and any(.route.rules[]; .action == "resolve")
    and (.route.rule_set | map(.tag) | index("geoip-ir") | not)
'

# Case 3: whitespace + jsDelivr URL — trim and @-form tag derivation
out="$(render 'DIRECT_DOMAIN_RULESET_URLS= https://cdn.jsdelivr.net/gh/chocolate4u/Iran-sing-box-rules@rule-set/geosite-ir.srs ')"
assert "case3 jsdelivr + whitespace" "$out" '
    (.route.rule_set[] | select(.tag == "geosite-ir") | .url)
        == "https://cdn.jsdelivr.net/gh/chocolate4u/Iran-sing-box-rules@rule-set/geosite-ir.srs"
'

# Case 4: listen/proxy overrides
out="$(render LISTEN_PORT=2080 PROXY_HOST=1.2.3.4 PROXY_PORT=9)"
assert "case4 overrides" "$out" '
    .inbounds[0].listen_port == 2080
    and (.outbounds[] | select(.tag == "proxy-out") | .server == "1.2.3.4" and .server_port == 9)
'

exit "$fail"
