#!/usr/bin/env python3
"""Dashboard preview server.

Development helper only: it serves web/static and fakes the adblockerpro
REST API with synthetic traffic, so the UI can be worked on without a Pi (or
even a Go toolchain) nearby. The real API is implemented in internal/api.

    python3 tools/preview/mock_api.py [port]
"""

from __future__ import annotations

import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[2] / "web" / "static"
START = time.time()

BLOCKED = [
    "ads.tiktok.com", "graph.facebook.com", "app-measurement.com",
    "doubleclick.net", "scribe.logs.roku.com", "googleads.g.doubleclick.net",
    "metrics.samsungcloudsolution.com", "device-metrics-us.amazon.com",
    "ssl.google-analytics.com", "cdn.flashtalking.com", "ads.samsung.com",
    "analytics.query.yahoo.com", "telemetry.lgsmartad.com",
]
ALLOWED = [
    "netflix.com", "api.hulu.com", "cdn.jsdelivr.net", "github.com",
    "ocsp.apple.com", "pubsub.googleapis.com", "youtubei.googleapis.com",
    "images-na.ssl-images-amazon.com", "weather.service.msn.com",
]
DEVICES = [
    ("192.168.1.21", "Living room TV"), ("192.168.1.34", "Fire Stick"),
    ("192.168.1.42", "Ada's iPhone"), ("192.168.1.55", "Work laptop"),
    ("192.168.1.77", "Xbox"), ("192.168.1.99", ""),
]
TYPES = ["A", "A", "A", "AAAA", "HTTPS", "TXT"]

state = {
    "queries": [],
    "total": 0,
    "blocked": 0,
    "cached": 0,
    "paused_until": None,
    "rules": [
        {"pattern": "*.doubleclick.net", "action": "block", "comment": "ads across apps and TVs", "group": ""},
        {"pattern": "clients4.google.com", "action": "allow", "comment": "Chromecast setup", "group": ""},
        {"pattern": "youtube.com", "action": "block", "comment": "bedtime", "group": "kids"},
    ],
    "devices": [
        {"match": "192.168.1.21", "name": "Living room TV", "group": "", "paused": False},
        {"match": "192.168.1.55", "name": "Work laptop", "group": "", "paused": True},
    ],
    "lists": [
        {"id": "a1", "title": "StevenBlack unified hosts", "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "enabled": True, "domains": 148231, "last_updated": "", "last_error": ""},
        {"id": "a2", "title": "AdGuard DNS filter", "url": "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", "enabled": True, "domains": 63104, "last_updated": "", "last_error": ""},
        {"id": "a3", "title": "Peter Lowe's ad servers", "url": "https://pgl.yoyo.org/adservers/serverlist.php", "enabled": True, "domains": 3521, "last_updated": "", "last_error": ""},
        {"id": "a4", "title": "OISD small", "url": "https://small.oisd.nl/", "enabled": True, "domains": 42887, "last_updated": "", "last_error": ""},
        {"id": "a5", "title": "Smart-TV & CTV trackers", "url": "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt", "enabled": True, "domains": 412, "last_updated": "", "last_error": ""},
    ],
    "schedules": [
        {"id": "s1", "name": "Bedtime", "enabled": True, "group": "kids", "days": ["all"],
         "start": "22:00", "end": "07:00", "mode": "block-all", "patterns": []},
        {"id": "s2", "name": "Dinner", "enabled": True, "group": "", "days": ["all"],
         "start": "18:00", "end": "19:00", "mode": "block-list",
         "patterns": ["*.tiktok.com", "instagram.com", "*.youtube.com"]},
    ],
    "dhcp": {
        "enabled": True, "server_ip": "192.168.1.2", "gateway": "192.168.1.1",
        "netmask": "255.255.255.0", "range_start": "192.168.1.100",
        "range_end": "192.168.1.200", "lease_hours": 12, "domain_name": "lan",
        "reservations": [{"mac": "aa:bb:cc:dd:ee:21", "ip": "192.168.1.21", "hostname": "living-room-tv"}],
    },
    "settings": {
        "listen": "0.0.0.0", "port": 53,
        "upstreams": ["1.1.1.1:53", "9.9.9.9:53"],
        "doh_upstreams": ["https://cloudflare-dns.com/dns-query", "https://dns.quad9.net/dns-query"],
        "prefer_doh": True, "sinkhole": "zero-ip", "custom_ipv4": "",
        "block_ttl": 60, "block_subdomains": True, "block_cname_cloaking": True,
        "block_https_records": False, "serve_stale": True,
        "cache_size": 20000, "cache_min_ttl": 30, "cache_max_ttl": 86400,
        "upstream_timeout_ms": 3500, "rate_limit_per_client": 0,
        "allowed_clients": [], "local_records": {},
        "request_dnssec": True, "doh_server": True,
        "conditional_forward": [{"domain": "home.arpa", "upstream": "192.168.1.1"}],
    },
}
for ls in state["lists"]:
    ls["last_updated"] = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def synth(n: int = 1) -> None:
    """Invent a few queries so the dashboard has something to show."""
    for _ in range(n):
        ip, name = random.choice(DEVICES)
        blocked = random.random() < 0.37
        domain = random.choice(BLOCKED if blocked else ALLOWED)
        cached = (not blocked) and random.random() < 0.45
        status = "blocked" if blocked else ("cached" if cached else "allowed")
        state["total"] += 1
        state["blocked"] += 1 if blocked else 0
        state["cached"] += 1 if cached else 0
        state["queries"].insert(0, {
            "time": now_iso(), "client": ip, "device": name, "domain": domain,
            "type": random.choice(TYPES), "status": status,
            "rule": domain if blocked else "",
            "source": "StevenBlack unified hosts" if blocked else "",
            "upstream": "" if blocked else ("cache" if cached else "https://cloudflare-dns.com/dns-query"),
            "rcode": "NOERROR",
            "ms": round(random.uniform(0.1, 1.2) if (blocked or cached) else random.uniform(8, 48), 2),
        })
    del state["queries"][600:]


def top(items, key, n=10):
    counts: dict[str, int] = {}
    for q in items:
        counts[q[key]] = counts.get(q[key], 0) + 1
    out = [{"name": k, "count": v} for k, v in counts.items()]
    out.sort(key=lambda x: -x["count"])
    return out[:n]


def timeline():
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    now -= timedelta(minutes=now.minute % 10)
    points = []
    for i in range(143, -1, -1):
        t = now - timedelta(minutes=10 * i)
        hour = t.hour
        base = 18 + int(55 * (0.35 + 0.65 * (1 if 17 <= hour <= 23 else 0.4)))
        total = max(0, int(random.gauss(base, 9)))
        points.append({"time": t.isoformat(), "total": total, "blocked": int(total * random.uniform(0.25, 0.45))})
    if points:
        points[-1]["total"] += len(state["queries"][:20])
    return points


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(ROOT), **kw)

    def log_message(self, fmt, *args):  # quieter output
        pass

    # ---- helpers -------------------------------------------------------
    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    # ---- routes --------------------------------------------------------
    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if not url.path.startswith("/api/"):
            return super().do_GET()

        synth(random.randint(1, 6))
        paused = state["paused_until"] and time.time() < state["paused_until"]

        if url.path == "/api/summary":
            qs = state["queries"]
            blocked_only = [x for x in qs if x["status"] == "blocked"]
            domains = sum(l["domains"] for l in state["lists"] if l["enabled"])
            return self.send_json({
                "summary": {
                    "total": state["total"], "blocked": state["blocked"],
                    "cached": state["cached"], "errors": 0,
                    "block_percent": (state["blocked"] / state["total"] * 100) if state["total"] else 0,
                    "avg_ms": 11.4, "clients": len(DEVICES), "since": now_iso(),
                    "top_allowed": top([x for x in qs if x["status"] != "blocked"], "domain"),
                    "top_blocked": top(blocked_only, "domain"),
                    "top_clients": top(qs, "device"),
                    "validated": int(state["total"] * 0.72),
                    "types": top(qs, "type", 6),
                    "timeline": timeline(),
                },
                "cache": {"entries": 4312, "max": 20000, "hits": state["cached"], "misses": max(1, state["total"] - state["cached"]), "stale": 3, "evicted": 0, "hit_rate": 62.5},
                "upstreams": [
                    {"name": "https://cloudflare-dns.com/dns-query", "healthy": True, "queries": state["total"], "errors": 0, "avg_ms": 18.2},
                    {"name": "https://dns.quad9.net/dns-query", "healthy": True, "queries": 12, "errors": 0, "avg_ms": 24.9},
                    {"name": "udp://1.1.1.1:53", "healthy": True, "queries": 0, "errors": 0, "avg_ms": 0},
                ],
                "schedules": {"count": len(state["schedules"]),
                              "active": [x for x in state["schedules"] if x["start"] <= datetime.now().strftime("%H:%M") < x["end"]]},
                "dhcp": {"enabled": state["dhcp"]["enabled"], "leases": len(DEVICES)},
                "history": {"enabled": True, "days": 30, "bytes": 48_300_000, "writes": state["total"]},
                "lists": {"domains": domains, "sources": len(state["lists"]), "last_update": state["lists"][0]["last_updated"]},
                "status": {"version": "preview", "uptime_s": int(time.time() - START), "dns_addr": "0.0.0.0:53",
                           "paused": bool(paused), "paused_until": datetime.fromtimestamp(state["paused_until"], timezone.utc).isoformat() if paused else "0001-01-01T00:00:00Z",
                           "sinkhole": state["settings"]["sinkhole"]},
            })

        if url.path == "/api/queries":
            rows = state["queries"]
            status = (q.get("status") or [""])[0]
            search = (q.get("search") or [""])[0].lower()
            if status:
                rows = [r for r in rows if r["status"] == status]
            if search:
                rows = [r for r in rows if search in r["domain"] or search in (r["device"] or "").lower() or search in r["client"]]
            limit = int((q.get("limit") or ["200"])[0])
            return self.send_json({"queries": rows[:limit], "count": len(rows[:limit])})

        if url.path == "/api/lists":
            return self.send_json({"sources": state["lists"], "domains": sum(l["domains"] for l in state["lists"] if l["enabled"])})
        if url.path == "/api/rules":
            return self.send_json({"rules": state["rules"]})
        if url.path == "/api/devices":
            seen = [{"ip": ip, "name": name, "queries": random.randint(40, 900), "blocked": random.randint(5, 400),
                     "last_seen": now_iso(), "group": "", "paused": False} for ip, name in DEVICES]
            return self.send_json({"devices": state["devices"], "seen": seen})
        if url.path == "/api/settings":
            return self.send_json({"dns": state["settings"], "lists": {"update_interval_hours": 24},
                                   "log": {"level": "info", "query_log_size": 20000}, "path": "/etc/adblockerpro/config.json"})
        if url.path == "/api/check":
            domain = (q.get("domain") or [""])[0].lower()
            hit = any(domain.endswith(b) or b.endswith(domain) for b in BLOCKED) or "ad" in domain or "track" in domain
            return self.send_json({"domain": domain, "group": "", "sinkhole": state["settings"]["sinkhole"],
                                   "decision": {"blocked": hit, "rule": domain if hit else "",
                                                "source": "StevenBlack unified hosts" if hit else "",
                                                "matched_domain": domain if hit else ""}})
        if url.path == "/api/history":
            rows = state["queries"]
            status = (q.get("status") or [""])[0]
            search = (q.get("search") or [""])[0].lower()
            if status:
                rows = [r for r in rows if r["status"] == status]
            if search:
                rows = [r for r in rows if search in r["domain"] or search in (r["device"] or "").lower()]
            offset = int((q.get("offset") or ["0"])[0])
            limit = int((q.get("limit") or ["100"])[0])
            total = len(rows) * 37  # pretend there is a month of it
            return self.send_json({"records": rows[offset:offset + limit], "total": total,
                                   "offset": offset, "limit": limit,
                                   "has_more": offset + limit < total, "enabled": True,
                                   "days": [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(30)],
                                   "bytes": 48_300_000})
        if url.path == "/api/history/daily":
            out = []
            for i in range(29, -1, -1):
                day = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
                total = random.randint(14000, 26000)
                out.append({"day": day, "total": total, "blocked": int(total * random.uniform(0.28, 0.42)),
                            "cached": int(total * 0.4), "clients": 6, "bytes": total * 70})
            return self.send_json({"days": out, "bytes": 48_300_000,
                                   "top_blocked": top([x for x in state["queries"] if x["status"] == "blocked"], "domain", 15),
                                   "top_allowed": top([x for x in state["queries"] if x["status"] != "blocked"], "domain", 15)})
        if url.path == "/api/schedules":
            nowhm = datetime.now().strftime("%H:%M")
            return self.send_json({"schedules": state["schedules"], "now": now_iso(),
                                   "active": [x for x in state["schedules"] if x["start"] <= nowhm < x["end"]],
                                   "next_change": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()})
        if url.path == "/api/dhcp":
            leases = [{"ip": ip, "mac": "aa:bb:cc:dd:ee:%02d" % (i + 16), "hostname": (name or "").lower().replace(" ", "-"),
                       "vendor": random.choice(["Roku", "AmazonTechnologies", "Apple", "Samsung", ""]),
                       "start": now_iso(), "expires": (datetime.now(timezone.utc) + timedelta(hours=9)).isoformat(),
                       "static": i == 0, "last_seen": now_iso()}
                      for i, (ip, name) in enumerate(DEVICES)]
            return self.send_json({"config": state["dhcp"], "leases": leases,
                                   "enabled": state["dhcp"]["enabled"], "count": len(leases)})
        if url.path == "/api/health":
            return self.send_json({"status": "ok", "version": "preview"})
        return self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        url = urlparse(self.path)
        data = self.body()
        if url.path == "/api/control":
            action = data.get("action")
            if action == "pause":
                state["paused_until"] = time.time() + 60 * int(data.get("minutes") or 5)
                return self.send_json({"status": "paused", "until": datetime.fromtimestamp(state["paused_until"], timezone.utc).isoformat()})
            if action == "resume":
                state["paused_until"] = None
                return self.send_json({"status": "filtering"})
            if action == "flush-cache":
                return self.send_json({"status": "ok", "flushed": 4312})
            if action == "reset-stats":
                state.update(total=0, blocked=0, cached=0, queries=[])
                return self.send_json({"status": "ok"})
        if url.path == "/api/rules":
            data.setdefault("action", "block")
            data.setdefault("group", "")
            state["rules"] = [r for r in state["rules"] if not (r["pattern"] == data.get("pattern") and r["action"] == data["action"])]
            state["rules"].append(data)
            return self.send_json(data)
        if url.path == "/api/devices":
            state["devices"] = [d for d in state["devices"] if d["match"] != data.get("match")]
            state["devices"].append(data)
            return self.send_json(data)
        if url.path == "/api/lists":
            state["lists"].append({"id": str(len(state["lists"]) + 1), "title": data.get("title") or data.get("url"),
                                   "url": data.get("url"), "enabled": True, "domains": random.randint(500, 90000),
                                   "last_updated": now_iso(), "last_error": ""})
            return self.send_json(state["lists"][-1])
        if url.path == "/api/lists/toggle":
            for l in state["lists"]:
                if l["id"] == data.get("id"):
                    l["enabled"] = bool(data.get("enabled"))
            return self.send_json({"status": "ok", "domains": sum(l["domains"] for l in state["lists"] if l["enabled"])})
        if url.path == "/api/lists/update":
            for l in state["lists"]:
                l["last_updated"] = now_iso()
            return self.send_json({"status": "ok", "domains": sum(l["domains"] for l in state["lists"] if l["enabled"])})
        if url.path == "/api/settings":
            state["settings"].update(data.get("dns") or {})
            return self.send_json({"status": "ok", "dns": state["settings"]})
        if url.path == "/api/schedules":
            data.setdefault("id", "s%d" % (len(state["schedules"]) + 1))
            state["schedules"] = [x for x in state["schedules"] if x["id"] != data["id"]]
            state["schedules"].append(data)
            return self.send_json(data)
        if url.path == "/api/dhcp":
            state["dhcp"].update(data)
            return self.send_json({"status": "ok", "config": state["dhcp"]})
        if url.path == "/api/dhcp/reservation":
            state["dhcp"].setdefault("reservations", []).append(data)
            return self.send_json(data)
        if url.path == "/api/restore":
            return self.send_json({"status": "restored", "rules": len(state["rules"]),
                                   "devices": len(state["devices"]), "schedules": len(state["schedules"]),
                                   "lists": len(state["lists"])})
        if url.path == "/api/login":
            return self.send_json({"status": "ok"})
        return self.send_json({"error": "not found"}, 404)

    def do_PUT(self):
        self.do_POST()

    def do_DELETE(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/api/rules":
            pattern = (q.get("pattern") or [""])[0]
            state["rules"] = [r for r in state["rules"] if r["pattern"] != pattern]
            return self.send_json({"status": "removed"})
        if url.path == "/api/devices":
            match = (q.get("match") or [""])[0]
            state["devices"] = [d for d in state["devices"] if d["match"] != match]
            return self.send_json({"status": "removed"})
        if url.path == "/api/schedules":
            sid = (q.get("id") or [""])[0]
            state["schedules"] = [x for x in state["schedules"] if x["id"] != sid]
            return self.send_json({"status": "removed"})
        if url.path == "/api/dhcp/reservation":
            mac = (q.get("mac") or [""])[0]
            state["dhcp"]["reservations"] = [r for r in state["dhcp"].get("reservations", []) if r["mac"] != mac]
            return self.send_json({"status": "removed"})
        if url.path == "/api/lists":
            lid = (q.get("id") or [""])[0]
            state["lists"] = [l for l in state["lists"] if l["id"] != lid]
            return self.send_json({"status": "removed"})
        return self.send_json({"error": "not found"}, 404)


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    synth(120)
    srv = HTTPServer(("0.0.0.0", port), Handler)
    print(f"dashboard preview on http://0.0.0.0:{port} (mock data)")
    srv.serve_forever()


if __name__ == "__main__":
    main()
