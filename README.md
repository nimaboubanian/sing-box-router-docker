# sing-box Iran Router (Docker)

A single fully-dockerized [sing-box](https://github.com/SagerNet/sing-box) container that routes ingress traffic by rule-sets, customized for Iran.

Ingress: one mixed port (SOCKS5 + HTTP) published to `127.0.0.1:1070` only.
Egress: three paths.

| Destination | Egress |
|---|---|
| Ads / malware / phishing / cryptominers | **Block** (rejected) |
| Private/LAN IPs, Iranian domains and IPs | **Direct** (host's default route) |
| Everything else | **Proxy** (existing `sb-lb` haproxy on the `vpndogs` network) |

Rule-sets come from [Chocolate4U/Iran-sing-box-rules](https://github.com/Chocolate4U/Iran-sing-box-rules)
(Iran-curated lists) and are **baked into the image at build time** under
`/usr/local/share/sing-box/rulesets`. At boot the entrypoint copies each one into
`/var/lib/sing-box/rulesets` after validating it, so **starting the container needs no network at
all** — not even to reach GitHub. `raw.githubusercontent.com` is unreliable from Iranian networks,
which is why the build falls back to `cdn.jsdelivr.net` (and `RULESET_MIRRORS`) before it gives up.

Only rule-sets with **no seed and no cached copy** — i.e. custom `*_RULESET_URLS` — are fetched at
boot, with retries, mirror fallback, and a `sing-box rule-set decompile` parse gate. A rule-set that
is truncated or empty is rejected rather than installed, since a silently-empty rule-set matches
nothing and sends all traffic to the proxy. If nothing valid can be had, the container exits
non-zero so compose's backoff retries it, rather than booting a router whose `reject`/direct
rule-sets are missing. A rule-set already in the volume that still parses is reused as-is.

**Freshness = image age.** CI rebuilds weekly (Mondays 04:00 UTC) so `latest` always carries current
lists; `docker compose pull && docker compose up -d` picks them up. Note GitHub disables scheduled
workflows after 60 days of repo inactivity — if the weekly run stops appearing, re-enable it in the
Actions tab or run `publish` manually via `workflow_dispatch`.

DNS for the routing decision (`resolve` before geoip matching) goes through DoH (`1.1.1.1`) via the
proxy; nothing local sees it.

## Routing decision order

1. `sniff` — recover the domain from TLS SNI / HTTP Host for IP-connecting clients
2. ads/malware/phishing/cryptominers rule-sets → `reject`
3. `EXTRA_REJECT_DOMAINS` → block
4. `EXTRA_PROXY_DOMAINS` → proxy (overrides everything direct below)
5. `EXTRA_REJECT_IPS` / `EXTRA_PROXY_IPS` → block/proxy for IP-connecting clients
6. private IPs → `direct`
7. `geosite-ir` (`.ir` TLD + known Iranian domains) → `direct`
8. `EXTRA_DIRECT_DOMAINS` → direct
9. `resolve` remaining domains via DoH (proxy detour)
10. `EXTRA_REJECT_IPS` / `EXTRA_PROXY_IPS` again — step 5's IP rules only saw IP-connecting clients; rule-sets and resolved domains are re-matched here (`EXTRA_PROXY_IPS` still overrides `geoip-ir`)
11. `geoip-ir` (Iranian IPs, incl. Iranian CDN/messenger ranges) → `direct`
12. `EXTRA_DIRECT_IPS` → direct
13. `final` → `proxy-out` (SOCKS to `lb:1081`)

If a destination appears in several `EXTRA_*` lists, the fixed rule order means
**reject > proxy > direct** — the first matching rule wins.

## Usage

```bash
./build.sh                 # or: BUILD_PROXY=socks5://127.0.0.1:1081 ./build.sh
docker compose up -d       # requires sb-lb to be up on vpndogs (non-Iranian traffic is sent to it)

curl --proxy socks5h://127.0.0.1:1070 https://api.ipify.org   # foreign → proxied
curl --proxy socks5h://127.0.0.1:1070 https://api.ipmyp.ir    # Iranian → direct
```

Verify with `docker logs sb-router` at `LOG_LEVEL=info`: each connection logs its
`outbound/socks[proxy-out]` or `outbound/direct[direct-out]` decision.

## Configuration

All knobs are environment variables (see `.env.example`; copy to `.env` to override):

| Var | Default | Notes |
|---|---|---|
| `LISTEN_PORT` | `1070` | Container-side listener; compose `ports:` must match if overridden |
| `PROXY_HOST` / `PROXY_PORT` | `lb` / `1081` | The SOCKS load balancer on `vpndogs` |
| `REJECT_RULESET_URLS` | ads/malware/phishing/cryptominers `.srs` URLs | Comma-separated |
| `DIRECT_DOMAIN_RULESET_URLS` | `geosite-ir.srs` | Comma-separated, matched before resolve |
| `DIRECT_IP_RULESET_URLS` | `geoip-ir.srs` | Comma-separated, matched after resolve |
| `RULESET_MIRRORS` | *(empty)* | Extra comma-separated rule-set sources tried after the URL's own jsDelivr mirror; `@file@` is replaced with the URL basename |
| `DOH_SERVER` | `1.1.1.1` | DoH endpoint for the resolve step (detoured via proxy) |
| `EXTRA_REJECT_DOMAINS` / `EXTRA_REJECT_IPS` | *(empty)* | Raw destinations to block, comma-separated |
| `EXTRA_PROXY_DOMAINS` / `EXTRA_PROXY_IPS` | *(empty)* | Raw destinations forced through the proxy — overrides the direct rule-sets |
| `EXTRA_DIRECT_DOMAINS` | *(empty)* | Raw domains routed direct, comma-separated, matched before resolve |
| `EXTRA_DIRECT_IPS` | *(empty)* | Raw IPs/CIDRs routed direct, comma-separated |
| `LOG_LEVEL` | `warn` | Use `info` to see route decisions |

Rule-set tags derive from URL basenames, so jsDelivr equivalents
(`https://cdn.jsdelivr.net/gh/chocolate4u/Iran-sing-box-rules@rule-set/<name>.srs`)
work as drop-in replacements. Fetched rule-sets are stored as `<tag>.srs` under
`/var/lib/sing-box/rulesets`, which the compose volume already persists.

Setting a `*_RULESET_URLS` var to **empty disables that group** — the route rule and its
rule-set definitions are omitted from the config.

Don't put the same rule-set URL in two lists — tags derive from the URL basename, and a
duplicate tag makes `sing-box check` fail at startup. Use an IP (not a hostname) for
`DOH_SERVER`: a hostname would be resolved through the local (Iranian) DNS.

## Build

`./build.sh` uses buildx on the host network. If GitHub is unreachable directly, route the
build through a proxy: `BUILD_PROXY=socks5://127.0.0.1:1081 ./build.sh`.

## Deploy from prebuilt images

Every push to `main` (and every `v*` tag) publishes `linux/amd64` + `linux/arm64` images to
[ghcr.io/nimaboubanian/sing-box-router](https://github.com/nimaboubanian/sing-box-router-docker/pkgs/container/sing-box-router)
and [Docker Hub](https://hub.docker.com/r/nimaboubanian/sing-box-router) via GitHub Actions.
Requires `sb-lb` on the `vpndogs` network (see [sing-box-client-docker](https://github.com/nimaboubanian/sing-box-client-docker)).

```bash
docker compose -f deploy/compose.yaml up -d
curl --proxy socks5h://127.0.0.1:1070 https://api.ipify.org   # proxied
curl --proxy socks5h://127.0.0.1:1070 https://api.ipmyp.ir    # direct
```

## Testing

```bash
scripts/test-render.sh   # contract tests for render + fetch-rulesets (run in the image)
```

Every case runs the container with `--network none` and fetches rule-sets over `file://`
URLs, so the suite is network-free. The container validates its rendered config with
`sing-box check` before starting; a bad config — or a rule-set that could not be fetched —
exits non-zero and docker's `restart: unless-stopped` backoff surfaces it in logs.
