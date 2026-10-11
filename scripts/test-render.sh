#!/usr/bin/env bash
# test-render.sh — contract tests for `entrypoint.sh render` + `fetch-rulesets`,
# run inside the image. Usage: ./build.sh && scripts/test-render.sh
# Everything here is network-free: fixtures are compiled inside the container and
# fetched over file:// URLs.
set -euo pipefail

IMG="${IMAGE:-sing-box-router:latest}"
fail=0
LAST_OUT=""

# render/render helpers all run with --network none: `render` must never touch
# the network, so make the container prove it.
docker_run() { docker run --rm --network none "$@"; }

render() { # render [KEY=VAL ...] -> rendered config JSON on stdout (exit status ignored)
    local envs=()
    local kv
    for kv in "$@"; do envs+=(-e "$kv"); done
    docker_run "${envs[@]}" --entrypoint /usr/local/bin/entrypoint.sh "$IMG" render || true
}

subcmd() { # subcmd <arg>... -> entrypoint.sh subcommand output
    docker_run --entrypoint /usr/local/bin/entrypoint.sh "$IMG" "$@"
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

eq() { # name want got
    if [[ "$2" == "$3" ]]; then
        echo "$1: PASS"
    else
        echo "$1: FAIL"
        printf '  want: %s\n  got:  %s\n' "$2" "$3" >&2
        fail=1
    fi
}

has() { # name needle haystack
    if [[ "$3" == *"$2"* ]]; then
        echo "$1: PASS"
    else
        echo "$1: FAIL"
        printf '  missing %q in:\n%s\n' "$2" "$3" >&2
        fail=1
    fi
}

lacks() { # name needle haystack
    if [[ "$3" != *"$2"* ]]; then
        echo "$1: PASS"
    else
        echo "$1: FAIL"
        printf '  unexpected %q in:\n%s\n' "$2" "$3" >&2
        fail=1
    fi
}

exit_is() { # name want cmd...  (runs cmd, stdout+stderr in $LAST_OUT)
    local name="$1" want="$2" got=0
    shift 2
    LAST_OUT="$("$@" 2>&1)" || got=$?
    eq "$name" "$want" "$got"
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
    (.route.rule_set[] | select(.tag == "geosite-ir") | .path)
        == "/var/lib/sing-box/rulesets/geosite-ir.srs"
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

# Case 8: every rendered rule-set is a local file under $RULESET_DIR
assert "case8 local rule-sets" "$(render)" '
    all(.route.rule_set[]; . as $r
        | $r.type == "local"
        and ($r.path | startswith("/var/lib/sing-box/rulesets/"))
        and ($r.path | endswith("/" + $r.tag + ".srs"))
        and ($r | has("url") | not))
'

# Case 9: mirror-url — githubusercontent maps to jsDelivr, idempotent otherwise
eq "case9 mirror-url githubusercontent" \
    "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geosite-ir.srs" \
    "$(subcmd mirror-url 'https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs')"
eq "case9 mirror-url jsdelivr" \
    "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geosite-ir.srs" \
    "$(subcmd mirror-url 'https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/geosite-ir.srs')"

# Case 10: corrupt primary source falls back to RULESET_MIRRORS, and the landed
# file is a real rule-set (decompile is the parse gate).
FIXTURES='
mkdir -p /tmp/src /tmp/alt
printf "{\"version\":3,\"rules\":[{\"domain_suffix\":[\".example.test\"]}]}" > /tmp/good.json
sing-box rule-set compile /tmp/good.json -o /tmp/alt/broken.srs
head -c 40 /dev/urandom > /tmp/src/broken.srs
'
fetch_env=(-e RULESET_DIR=/rulesets -e SEED_DIR=/empty -e DIRECT_DOMAIN_RULESET_URLS= -e DIRECT_IP_RULESET_URLS=)
exit_is "case10 corrupt primary -> mirror fallback" 0 \
    docker_run "${fetch_env[@]}" \
        -e REJECT_RULESET_URLS=file:///tmp/src/broken.srs \
        -e RULESET_MIRRORS=file:///tmp/alt/@file@ \
        --entrypoint /bin/sh "$IMG" -c "$FIXTURES"'/usr/local/bin/entrypoint.sh fetch-rulesets && sing-box rule-set decompile /rulesets/broken.srs -o /dev/null && echo MIRROR_FALLBACK_OK'
has "case10 mirror was used" "fetching file:///tmp/alt/broken.srs" "$LAST_OUT"
has "case10 corrupt source rejected" "source unusable" "$LAST_OUT"

# Case 11: no source at all is fatal, loudly — never boot with missing rule-sets
exit_is "case11 all sources fail" 1 \
    docker_run "${fetch_env[@]}" \
        -e REJECT_RULESET_URLS=file:///tmp/src/broken.srs \
        --entrypoint /bin/sh "$IMG" -c "$FIXTURES"'/usr/local/bin/entrypoint.sh fetch-rulesets'
has "case11 fatal logged" "FATAL: rule-set broken could not be fetched from any source" "$LAST_OUT"

# Case 12: every list disabled is not a failure — nothing to fetch, nothing to load
exit_is "case12 all lists disabled" 0 \
    docker_run -e RULESET_DIR=/rulesets -e REJECT_RULESET_URLS= \
        -e DIRECT_DOMAIN_RULESET_URLS= -e DIRECT_IP_RULESET_URLS= \
        --entrypoint /usr/local/bin/entrypoint.sh "$IMG" fetch-rulesets
has "case12 fetch skipped" "no rule-sets configured" "$LAST_OUT"

# Case 13: the real boot sequence — fetch, render, `sing-box check` on local files
BOOT_FIXTURES='
mkdir -p /tmp/src
printf "{\"version\":3,\"rules\":[{\"domain_suffix\":[\".example.test\"]}]}" > /tmp/good.json
sing-box rule-set compile /tmp/good.json -o /tmp/src/ads.srs
sing-box rule-set compile /tmp/good.json -o /tmp/src/ir.srs
'
exit_is "case13 fetch+render+check" 0 \
    docker_run -e RULESET_DIR=/rulesets -e SEED_DIR=/empty \
        -e REJECT_RULESET_URLS=file:///tmp/src/ads.srs \
        -e DIRECT_DOMAIN_RULESET_URLS=file:///tmp/src/ir.srs \
        -e DIRECT_IP_RULESET_URLS= \
        --entrypoint /bin/sh "$IMG" -c "$BOOT_FIXTURES"'/usr/local/bin/entrypoint.sh fetch-rulesets && /usr/local/bin/entrypoint.sh render > /tmp/c.json && sing-box check -c /tmp/c.json && echo BOOT_OK'
has "case13 both rule-sets validated" "all 2 rule-set(s) fetched and validated" "$LAST_OUT"

# Case 14: the image ships the rule-sets, so boot resolves them with no network
# at all — even though every configured URL is unreachable.
SEED_FIXTURES='
mkdir -p /seed
printf "{\"version\":3,\"rules\":[{\"domain_suffix\":[\".example.test\"]}]}" > /tmp/good.json
sing-box rule-set compile /tmp/good.json -o /seed/ads.srs
sing-box rule-set compile /tmp/good.json -o /seed/ir.srs
'
exit_is "case14 seed resolves with no network" 0 \
    docker_run -e RULESET_DIR=/rulesets -e SEED_DIR=/seed \
        -e REJECT_RULESET_URLS=file:///nonexistent/ads.srs \
        -e DIRECT_DOMAIN_RULESET_URLS=file:///nonexistent/ir.srs \
        -e DIRECT_IP_RULESET_URLS= \
        --entrypoint /bin/sh "$IMG" -c "$SEED_FIXTURES"'/usr/local/bin/entrypoint.sh fetch-rulesets && /usr/local/bin/entrypoint.sh render > /tmp/c.json && sing-box check -c /tmp/c.json && echo SEED_BOOT_OK'
has "case14 seeded from image" "seeding" "$LAST_OUT"

# Case 15: a corrupt seed must not be trusted — the fetch path takes over, so a
# bad file in the image can never become silently wrong routing.
CORRUPT_SEED_FIXTURES='
mkdir -p /seed /tmp/src
head -c 40 /dev/urandom > /seed/broken.srs
printf "{\"version\":3,\"rules\":[{\"domain_suffix\":[\".example.test\"]}]}" > /tmp/good.json
sing-box rule-set compile /tmp/good.json -o /tmp/src/broken.srs
'
exit_is "case15 corrupt seed falls back to fetch" 0 \
    docker_run -e RULESET_DIR=/rulesets -e SEED_DIR=/seed \
        -e DIRECT_DOMAIN_RULESET_URLS= -e DIRECT_IP_RULESET_URLS= \
        -e REJECT_RULESET_URLS=file:///tmp/src/broken.srs \
        --entrypoint /bin/sh "$IMG" -c "$CORRUPT_SEED_FIXTURES"'/usr/local/bin/entrypoint.sh fetch-rulesets && sing-box rule-set decompile /rulesets/broken.srs -o /dev/null && echo CORRUPT_SEED_OK'
has "case15 corrupt seed rejected" "fetching file:///tmp/src/broken.srs" "$LAST_OUT"
lacks "case15 never seeded from corrupt file" "seeding" "$LAST_OUT"

# Case 16: the shipped seed covers exactly the default rule-sets, and every one
# of them parses. Catches an upstream rename (weekly build would still succeed
# if a URL 404s to an HTML error page that somehow decompiles) or a dropped file.
seed_tags() { # -> seed tags, validated and sorted; errors on stderr
    docker_run --entrypoint /bin/sh "$IMG" -c '
d=/usr/local/share/sing-box/rulesets
[ -d "$d" ] || { echo "no seed dir $d" >&2; exit 1; }
for f in "$d"/*.srs; do
    [ -s "$f" ] || { echo "empty seed: $f" >&2; exit 1; }
    sing-box rule-set decompile "$f" -o /dev/null 2>/dev/null \
        || { echo "unparseable seed: $f" >&2; exit 1; }
done
ls "$d" | sed "s/\.srs$//" | sort'
}
eq "case16 image ships the default seed" \
    "$(printf '%s\n' geosite-category-ads-all geosite-cryptominers geosite-ir \
        geosite-malware geosite-phishing geoip-ir | sort)" \
    "$(seed_tags)"

exit "$fail"
