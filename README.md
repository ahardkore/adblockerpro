# adblockerpro

A Raspberry Pi you plug into your home network that stops ads on **every**
device behind it — phones, laptops, consoles, and especially the streaming
hardware you cannot install an ad blocker on: smart TVs, Fire Sticks, Roku,
Apple TV, Chromecast.

It is a filtering DNS resolver written in Go with zero external dependencies:
one static binary, a few hundred KB of RAM, and a dashboard at
`http://<pi-ip>:8080`.

```
  TV / phone / console ──DNS──▶  Raspberry Pi (adblockerpro)  ──DoH──▶  1.1.1.1
                                 │
                                 ├─ ad or tracker hostname → 0.0.0.0 (never loads)
                                 └─ everything else        → cached, forwarded
```

## How it works

Every app on every device asks DNS "where is `ads.example.com`?" before it can
load anything. adblockerpro answers that question for the whole LAN. If the
hostname is on a blocklist it returns `0.0.0.0` and the ad, tracker or
telemetry beacon never gets a connection. Real traffic is forwarded upstream
over DNS-over-HTTPS and cached locally, so browsing usually gets *faster*.

Features:

- **Network-wide filtering** — nothing to install on client devices.
- **~1 million+ domains** from StevenBlack, AdGuard DNS, OISD, Peter Lowe and
  a dedicated smart-TV/CTV tracker list; refreshed daily. Subscribed
  **allowlists** can override them.
- **CNAME-cloak blocking** — catches trackers hidden behind first-party
  hostnames, which most hosts-file blockers miss.
- **Built-in DHCP server** — hand out addresses yourself and every device
  gets this Pi as its DNS whether it likes it or not, with hostnames and
  MACs learned automatically and one-click address reservations.
- **Schedules** — bedtime, homework hours, "no socials at dinner", per rule
  group, with windows that wrap past midnight.
- **Long-term history** — every query kept for 30 days (configurable) in
  append-only daily shards, searchable and paginated, exportable as JSONL.
- **Per-device policy** — name a device, put it in a rule group, or turn
  filtering off entirely for one TV without touching the rest of the house.
- **Live dashboard** — query log, activity charts, top blocked domains,
  per-device stats, one-click allow/block, pause button.
- **DNS-over-HTTPS upstreams** so your ISP cannot read or hijack lookups —
  and an optional **DoH server** of your own at `/dns-query`.
- **DNSSEC-aware** — sets the DO bit and tracks which answers came back
  authenticated (AD), shown as a percentage on the dashboard.
- **Prometheus metrics** at `/metrics`, and **backup/restore** of the whole
  box as a single JSON file.
- **Cache with stale-serving** — if the internet drops, the LAN keeps
  resolving what it already knows.
- **Safe by default** — only answers private/loopback clients, so the Pi can
  never be abused as an open resolver.

### How it compares to Pi-hole

| | adblockerpro | Pi-hole v6 |
| --- | --- | --- |
| Engine | one Go binary, standard library only | `pihole-FTL` (C) built on dnsmasq |
| Blocklists / allowlists | ✓ / ✓ | ✓ / ✓ (Antigravity) |
| CNAME-cloak blocking | ✓ | ✓ |
| Encrypted upstream (DoH) | built in | needs cloudflared or unbound |
| DoH **server** for your own clients | ✓ | ✗ |
| DHCP server | ✓ (pure Go) | ✓ (dnsmasq) |
| Long-term query history | ✓ 30 days, append-only shards | ✓ SQLite |
| Time-based rules / bedtime | ✓ native | ✗ (cron + API) |
| Per-device pause | ✓ | partial (groups) |
| Prometheus metrics | ✓ built in | third-party exporter |
| Backup / restore | ✓ one JSON file | ✓ Teleporter |
| Native HTTPS for the UI | ✓ self-signed out of the box | ✓ |
| Password storage | PBKDF2-SHA256 + expiring sessions | balloon/scrypt + sessions |
| Command line client | ✓ `abpctl` | ✓ `pihole` |
| Cache survives a reboot | ✓ | ✗ |
| Query coalescing + prefetch | ✓ | prefetch ✗ |
| DNSSEC | DO bit + AD tracking, validation delegated to the upstream | full local validation |
| Maturity | young | a decade of field use |

The one place Pi-hole is still genuinely ahead is **local DNSSEC
validation** — we ask a validating upstream (Quad9, Cloudflare) to do the
cryptography and report the result, rather than verifying the signature
chain on the Pi itself.

### Speed

Three things keep the resolver out of the way:

- **Coalescing** — when several devices ask for the same hostname inside the
  same few milliseconds (exactly what happens when a household starts
  streaming) one query goes upstream and everybody shares the answer.
- **Prefetching** — entries that get asked for repeatedly are refreshed in
  the background shortly before their TTL runs out, so the cache rarely
  misses on the names you actually use.
- **A cache that survives reboots** — the cache is written to
  `<data-dir>/cache.bin` on shutdown and reloaded on start, with anything
  that expired in the meantime dropped. No cold-start penalty after an
  update or a power cut.

## Hardware

| Part | Notes |
| --- | --- |
| Raspberry Pi | Zero 2 W, 3, 4 or 5. A Pi Zero 2 W handles a busy family network. |
| microSD card | 8 GB+, any class. |
| Power supply | The official one — brownouts corrupt SD cards. |
| Ethernet (optional) | Wired is steadier than Wi-Fi for something the whole LAN depends on. |

Flash **Raspberry Pi OS Lite (64-bit)** with the Raspberry Pi Imager, enable
SSH and your Wi-Fi in the Imager's settings gear, boot it, and SSH in.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/ahardkore/adblockerpro/main/deploy/install.sh | sudo bash
```

The installer picks the right binary for your Pi, creates a locked-down
`adblockerpro` service user, frees port 53 if `systemd-resolved` is holding
it, installs the systemd unit and starts it.

From a clone instead:

```bash
git clone https://github.com/ahardkore/adblockerpro && cd adblockerpro
make pi64                      # or: make pi32 / make pi
sudo ./deploy/install.sh --local
```

## Point your network at it

1. Give the Pi a **static IP** or a DHCP reservation on your router.
2. Router → DHCP settings → set **DNS server** to the Pi's IP. (Some routers
   call this "Primary DNS". Leave the secondary blank, or set it to the Pi
   as well — a secondary pointing at your ISP will leak ads through.)
3. Reboot your TVs and streaming sticks, or wait for their DHCP lease to
   renew.
4. Optional, but it closes the biggest hole: in the router's firewall, block
   outbound **port 53** for every device except the Pi. Plenty of streaming
   hardware ships with hard-coded DNS servers (Google, Amazon) and will
   happily ignore your DHCP settings otherwise.

No router control? Set the Pi as the DNS server manually in each device's
network settings.

## Website

A four-page static site lives in [`site/`](site/): a landing page, the
hardware shopping list, the eight-step setup walkthrough and a help/FAQ page.
It has no build step — open `index.html`, or publish the folder anywhere.

`.github/workflows/pages.yml` deploys it to GitHub Pages on pushes to `main`
(turn it on once under **Settings → Pages → Source: GitHub Actions**).

**Affiliate links live in one file:** [`site/products.json`](site/products.json).
Put your Amazon Associates tag in `affiliate_tag` and the product URLs in each
`url` field; the tag is appended automatically, links are rendered with
`rel="nofollow sponsored noopener"`, and the disclosure line is printed under
every kit. Products with an empty `url` show a greyed-out "link coming soon"
button, so a partly filled list still looks deliberate. See
[`site/README.md`](site/README.md).

## Dashboard

`http://<pi-ip>:8080`

First time you open it, a **setup wizard** walks you through the whole thing:
pick a protection level (Gentle / Balanced / Strict, which just swaps the
blocklists), read off the exact address to type into your router — with
per-brand instructions for a dozen common routers — press **Run the test**,
and set a dashboard password. The test checks four things and says in plain
words what to do about anything that fails. Re-run it any time from
**Settings → Run setup again**.

Every tab carries a one-paragraph plain-English explanation, and the **? Help**
button opens a glossary plus a "something stopped working" checklist.

- **Overview** — queries, block rate, cache hit rate, activity chart, and a
  "is this domain blocked?" checker for when an app misbehaves.
- **Query log** — live tail of every lookup with one-click allow/block.
- **Blocklists** — add any hosts-format, plain-domain or Adblock-style URL,
  toggle lists on and off, refresh on demand.
- **Rules** — your own patterns: `ads.example.com`, `*.example.com`, or
  `/^ads?[0-9]*\./` regexes. Allow rules always beat block rules.
- **Devices** — name what the resolver has seen, assign rule groups, pause
  filtering per device, and open a **per-device report**: its busiest and
  most-blocked domains, block rate, and an hour-by-hour chart that makes
  "the TV phones home at 3 a.m." impossible to miss.
- **History** — 30 days of queries, searchable and paginated, with a daily
  bar chart and JSONL export.
- **Schedules** — time windows per group: block everything, block a list, or
  allow only a list.
- **DHCP** — pool settings, live leases, pinned addresses.
- **Settings** — sinkhole mode, upstreams, DoH in and out, DNSSEC,
  conditional forwarding, cache, prefetching, rate limits, backup and
  restore, plus a **Security** box for the password, HTTPS and sessions.

### Locking it down

```bash
sudo adblockerpro -set-password          # prompts, stores a PBKDF2 hash
```

The password is never written to disk in the clear: the config holds a
PBKDF2-HMAC-SHA256 hash (210 000 iterations) and logging in sets an opaque,
expiring `abp_session` cookie. Five bad guesses from one address lock that
address out for five minutes. `web.admin_token` still exists for scripts
(`X-API-Key`), and you can change the password from the Settings tab, where
you can also sign every other browser out.

For HTTPS, tick *Serve the dashboard over HTTPS* (or set `web.tls.enabled`)
and restart. With no certificate configured the service generates a
self-signed one in the data directory — valid for five years, renewed
automatically, with every local IP and hostname in its SAN list — and prints
its fingerprint in the log and the Settings tab so you can check the
browser's warning against it. Point a real certificate at it with
`web.tls.cert_file` / `web.tls.key_file`.

### abpctl, from the terminal

The release ships a second binary for when you are already on SSH:

```bash
abpctl status               # queries, block rate, cache, upstream health
abpctl top -n 15            # busiest and most-blocked domains
abpctl tail -f              # live query log
abpctl device 192.168.1.21  # per-device drill-down
abpctl pause 15m            # and: resume, flush
abpctl check ads.example.com
abpctl backup ~/abp-backup.json
```

It talks to the local API; set `ABP_ADDR` and `ABP_TOKEN` (or pass `-addr`
and `-token`) when the dashboard is not on `http://127.0.0.1:8080`.

## Configuration

`/etc/adblockerpro/config.json` (see [`deploy/config.example.json`](deploy/config.example.json)).
Everything in the Settings tab writes back here; edits made by hand take
effect on `systemctl restart adblockerpro`.

Notable keys:

| Key | What it does |
| --- | --- |
| `dns.sinkhole` | `zero-ip` (default), `nxdomain`, `refused` or `custom-ip`. |
| `dns.prefer_doh` | Try DNS-over-HTTPS first, fall back to plain UDP. |
| `dns.prefetch` | Refresh popular cache entries ~20 s before they expire. |
| `dns.block_subdomains` | A listed domain also covers its subdomains. |
| `dns.block_cname_cloaking` | Re-check CNAME targets of allowed answers. |
| `dns.block_https_records` | Drop HTTPS/SVCB records (stops some ECH-based bypasses). |
| `dns.allowed_clients` | Restrict who may query; blank means private networks only. |
| `dns.local_records` | Static names, e.g. `{"nas.home": "192.168.1.10"}`. |
| `log.anonymize_clients` | Store hashed client addresses in the query log. |
| `dns.request_dnssec` | Ask upstreams to validate; the AD bit is tracked per query. |
| `dns.doh_server` | Serve DNS-over-HTTPS at `/dns-query` on the dashboard port. |
| `dns.conditional_forward` | Send a domain suffix to a specific resolver (e.g. your router). |
| `history.enabled`, `history.retention_days` | Long-term query store and how long to keep it. |
| `dhcp.*` | Built-in DHCP server: pool, gateway, lease time, reservations. |
| `schedules[]` | Time-based rules; see the Schedules tab. |
| `web.admin_password_hash` | PBKDF2 hash; set it with `adblockerpro -set-password`. |
| `web.session_hours` | How long a dashboard login lasts (default 168). |
| `web.tls.*` | HTTPS for the dashboard: `enabled`, `port`, `cert_file`, `key_file`, `redirect_http`. |

### Running the DHCP server

Turn **off** your router's DHCP server first — two servers on one LAN fight
and lose. Then set `dhcp.enabled` (or use the DHCP tab), give it the Pi's
own IP, the router's IP as the gateway, and a pool that does not overlap
anything static. Restart the service. Clients then get this Pi as their DNS
automatically, and the dashboard starts naming devices by their hostnames.

### DNS-over-HTTPS for your phone

Enable `dns.doh_server` and `web.tls.enabled`, then point a browser's secure
DNS at `https://<pi>:8443/dns-query`. Android's "Private DNS" insists on a
publicly trusted certificate, so for phones put a real certificate in
`web.tls.cert_file` (or a reverse proxy in front). Your phone then keeps the
same filtering when it leaves the house.

## Troubleshooting

```bash
systemctl status adblockerpro
journalctl -u adblockerpro -f
adblockerpro --check ads.example.com     # exit code 1 means blocked
dig @<pi-ip> doubleclick.net             # expect 0.0.0.0
dig @<pi-ip> example.com                 # expect a real answer
```

**An app broke.** Open the query log, filter by the device, look for a
blocked domain with the app's name in it, hit *allow*. The change is live
immediately.

**Port 53 already in use.** Something else (dnsmasq, bind9, unbound,
systemd-resolved) owns it. The installer handles systemd-resolved; stop the
others or move them to another port.

**A device ignores the filter.** It has hard-coded DNS. Block outbound port
53 at the router, or for Android/iOS also turn off "Private DNS" /
"iCloud Private Relay" on that device.

## Development

```bash
make test          # unit tests
make vet
make run           # DNS on :5353, dashboard on :8080, no root needed
dig @127.0.0.1 -p 5353 doubleclick.net
```

The dashboard is plain HTML/CSS/JS in `web/static`, embedded into the binary
with `go:embed` — no build step, no node_modules.

```
cmd/adblockerpro      entry point, flags, wiring
internal/dnsmsg       DNS wire format: parsing, sinkhole answers, TTL ageing
internal/blocklist    matching engine, list parser, downloader
internal/resolver     upstream pool (UDP + DoH) and the response cache
internal/server       UDP/TCP listeners and the per-query decision path
internal/devices      client IP → device policy, DHCP-learned names
internal/schedule     time-based rules
internal/dhcp         DHCPv4 server: packets, leases, reservations
internal/history      long-term query store (append-only daily shards)
internal/stats        in-memory query log, counters, timeline
internal/api          REST API, DoH server, metrics, backup, dashboard
web/static            the dashboard itself
deploy/               systemd unit, installer, example config
```

### API

Every dashboard action is a plain REST call (add `-H "X-API-Key: <token>"`
when `web.admin_token` is set):

```
GET  /api/summary?hours=24
GET  /api/queries?limit=200&search=&status=blocked
GET  /api/check?domain=ads.example.com
GET  /api/lists        POST /api/lists        DELETE /api/lists?id=
POST /api/lists/update POST /api/lists/toggle
GET  /api/rules        POST /api/rules        DELETE /api/rules?pattern=&action=
GET  /api/devices      POST /api/devices      DELETE /api/devices?match=
GET  /api/settings     PUT  /api/settings
POST /api/control      {"action":"pause|resume|flush-cache|reset-stats","minutes":5}
GET  /api/history?from=&to=&search=&status=&limit=100&offset=0
GET  /api/history/daily?days=30          GET /api/history/export
GET  /api/schedules    POST /api/schedules    DELETE /api/schedules?id=
GET  /api/dhcp         POST /api/dhcp         POST/DELETE /api/dhcp/reservation
GET  /api/devices/suggest
GET  /api/devices/clients?days=7
GET  /api/devices/report?client=192.168.1.21&days=7
POST /api/login        POST /api/logout
POST /api/password     {"current":"…","new":"…"}
GET  /api/sessions     DELETE /api/sessions
GET  /api/backup       POST /api/restore
GET  /api/health
GET  /metrics                            # Prometheus
GET|POST /dns-query                      # RFC 8484 DNS-over-HTTPS
```

## Licence

MIT — see [LICENSE](LICENSE).
