# sing-box Iran Router (Docker)

A single fully-dockerized [sing-box](https://github.com/SagerNet/sing-box) container that routes ingress traffic by rule-sets, customized for Iran.

Ingress: one mixed port (SOCKS5 + HTTP) published to `127.0.0.1:1070` only.
Egress: three paths.

| Destination | Egress |
|---|---|
| Ads / malware / phishing / cryptominers | **Block** (rejected) |
| Private/LAN IPs, Iranian domains and IPs | **Direct** (host's default route) |
| Everything else | **Proxy** (existing `sb-lb` haproxy on the `vpndogs` network) |

Rule-sets are fetched at startup from [Chocolate4U/Iran-sing-box-rules](https://github.com/Chocolate4U/Iran-sing-box-rules)
(Iran-curated lists), cached in a named volume so restarts don't refetch, and downloaded through the proxy
detour — `raw.githubusercontent.com` is unreliable from Iranian networks. DNS for the routing decision
(`resolve` before geoip matching) goes through DoH (`1.1.1.1`) via the proxy; nothing local sees it.

## Routing decision order

1. `sniff` — recover the domain from TLS SNI / HTTP Host for IP-connecting clients
2. ads/malware/phishing/cryptominers → `reject`
3. private IPs → `direct`
4. `geosite-ir` (`.ir` TLD + known Iranian domains) → `direct`
5. `resolve` remaining domains via DoH (proxy detour)
6. `geoip-ir` (Iranian IPs, incl. Iranian CDN/messenger ranges) → `direct`
7. `final` → `proxy-out` (SOCKS to `lb:1081`)

## Usage

```bash
./build.sh                 # or: BUILD_PROXY=socks5://127.0.0.1:1081 ./build.sh
docker compose up -d       # requires sb-lb to be up on vpndogs (rule-set downloads detour through it)

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
| `DOH_SERVER` | `1.1.1.1` | DoH endpoint for the resolve step (detoured via proxy) |
| `LOG_LEVEL` | `warn` | Use `info` to see route decisions |

Rule-set tags derive from URL basenames, so jsDelivr equivalents
(`https://cdn.jsdelivr.net/gh/chocolate4u/Iran-sing-box-rules@rule-set/<name>.srs`)
work as drop-in replacements.

Setting a `*_RULESET_URLS` var to **empty disables that group** — the route rule and its
rule-set definitions are omitted from the config.

## Build

`./build.sh` uses buildx on the host network. If GitHub is unreachable directly, route the
build through a proxy: `BUILD_PROXY=socks5://127.0.0.1:1081 ./build.sh`.

## Testing

```bash
scripts/test-render.sh   # 5 contract tests for the rendered config (run in the image)
```

The container validates its rendered config with `sing-box check` before starting; a bad
config exits non-zero and docker's `restart: unless-stopped` backoff surfaces it in logs.
