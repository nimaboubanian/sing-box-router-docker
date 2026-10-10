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
    local name="$1" json="$2" filter="$3" res
    if res="$(printf '%s' "$json" | jq -e "$filter" 2>&1)"; then
        echo "$name: PASS"
    else
        echo "$name: FAIL"
        printf '%s\n' "$res" >&2
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

# Case 5: compose interpolation honors empty (disable) over defaults
cfg="$(DIRECT_IP_RULESET_URLS= docker compose config --format json 2>/dev/null)" || true
assert "case5 compose empty-to-disable" "$cfg" '
    .services.router.environment.DIRECT_IP_RULESET_URLS == ""
    and (.services.router.environment.DIRECT_DOMAIN_RULESET_URLS | test("geosite-ir\\.srs$"))
    and (.services.router.environment.LISTEN_PORT | tonumber) == 1070
'

# Case 6: extra raw direct destinations — domain before resolve, IP after
out="$(render EXTRA_DIRECT_DOMAINS=' example.com, foo.org ' EXTRA_DIRECT_IPS='10.8.0.0/24')"
assert "case6 extra destinations" "$out" '
    any(.route.rules[]; .domain_suffix == ["example.com", "foo.org"] and .outbound == "direct-out")
    and any(.route.rules[]; .ip_cidr == ["10.8.0.0/24"] and .outbound == "direct-out")
    and (([.route.rules[] | has("domain_suffix")] | index(true))
         < ([.route.rules[] | .action] | index("resolve")))
    and (([.route.rules[] | has("ip_cidr")] | index(true))
         > ([.route.rules[] | .action] | index("resolve")))
'

# Case 7: reject/proxy extras — priority reject > proxy > direct (first match wins).
# IP extras are rendered twice (pre-private + post-resolve) so both IP-connected
# and domain-connected (resolved) clients honor them.
out="$(render EXTRA_REJECT_DOMAINS=bad.example EXTRA_PROXY_DOMAINS=bank.example.ir EXTRA_PROXY_IPS=10.10.0.0/24 EXTRA_REJECT_IPS=10.9.0.0/24 EXTRA_DIRECT_DOMAINS=bank.example.ir,bad.example)"
assert "case7 extra reject/proxy priority" "$out" '
    any(.route.rules[]; .domain_suffix == ["bad.example"] and .action == "reject")
    and any(.route.rules[]; .domain_suffix == ["bank.example.ir"] and .outbound == "proxy-out")
    and any(.route.rules[]; .domain_suffix == ["bank.example.ir", "bad.example"] and .outbound == "direct-out")
    and (.route.rules | map(select(.domain_suffix)) | map(.action // .outbound))
        == ["reject", "proxy-out", "direct-out"]
    and (([.route.rules[] | has("ip_cidr")] | indices(true)) as $i
         | ([.route.rules[] | .ip_is_private] | index(true)) as $p
         | ([.route.rules[] | .action] | index("resolve")) as $r
         | ($i | length) == 4
         and $i[0] < $p and $i[1] < $p and $r < $i[2] and $r < $i[3])
'

exit "$fail"
