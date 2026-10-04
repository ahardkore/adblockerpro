/* adblockerpro dashboard — plain ES2017, no build step. */
(() => {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => Array.from(document.querySelectorAll(sel));
  const fmt = new Intl.NumberFormat();

  let timer = null;
  let activeTab = "overview";

  /* ---------- helpers ---------- */

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      ...opts,
    });
    if (res.status === 401) {
      $("#login").classList.remove("hidden");
      throw new Error("unauthorized");
    }
    const text = await res.text();
    let data = {};
    try { data = text ? JSON.parse(text) : {}; } catch (_) { data = { error: text }; }
    if (!res.ok) throw new Error(data.error || res.statusText);
    return data;
  }

  function toast(msg, bad) {
    const el = $("#toast");
    el.textContent = msg;
    el.style.borderColor = bad ? "#5a2a33" : "";
    el.classList.add("show");
    setTimeout(() => el.classList.remove("show"), 2600);
  }

  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));

  function compact(n) {
    n = Number(n || 0);
    if (n >= 1e9) return (n / 1e9).toFixed(1) + "B";
    if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
    return fmt.format(n);
  }

  function bytes(n) {
    n = Number(n || 0);
    if (n >= 1 << 30) return (n / (1 << 30)).toFixed(1) + " GB";
    if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + " MB";
    if (n >= 1024) return (n / 1024).toFixed(0) + " kB";
    return n + " B";
  }

  function duration(sec) {
    sec = Math.max(0, Math.floor(sec || 0));
    const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
    if (d) return `${d}d ${h}h`;
    if (h) return `${h}h ${m}m`;
    return `${m}m`;
  }

  function ago(iso) {
    if (!iso || iso.startsWith("0001")) return "never";
    const s = (Date.now() - new Date(iso).getTime()) / 1000;
    if (s < 60) return `${Math.floor(s)}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    return `${Math.floor(s / 86400)}d ago`;
  }

  const clock = (iso) => new Date(iso).toLocaleTimeString([], { hour12: false });

  /* ---------- overview ---------- */

  async function loadSummary() {
    const d = await api("/api/summary?hours=24");
    const s = d.summary || {};

    $("#stat-total").textContent = compact(s.total);
    $("#stat-clients").textContent = `${s.clients || 0} device${s.clients === 1 ? "" : "s"} seen`;
    $("#stat-blocked").textContent = compact(s.blocked);
    $("#stat-blocked-pct").textContent = `${(s.block_percent || 0).toFixed(1)}% of all queries`;
    $("#stat-domains").textContent = compact(d.lists.domains);
    $("#stat-lists").textContent = `${d.lists.sources} lists · updated ${ago(d.lists.last_update)}`;
    $("#stat-cache").textContent = `${(d.cache.hit_rate || 0).toFixed(0)}%`;
    $("#stat-cache-entries").textContent = `${compact(d.cache.entries)} / ${compact(d.cache.max)} entries`;
    $("#stat-latency").textContent = `${(s.avg_ms || 0).toFixed(1)} ms`;
    $("#stat-uptime").textContent = `up ${duration(d.status.uptime_s)} · v${d.status.version}`;
    $("#dns-addr").textContent = `DNS on ${d.status.dns_addr} · sinkhole: ${d.status.sinkhole}`;

    const pill = $("#status-pill");
    if (d.status.paused) {
      pill.textContent = `paused until ${clock(d.status.paused_until)}`;
      pill.className = "pill paused";
      $("#btn-pause").textContent = "Resume";
    } else {
      pill.textContent = "filtering";
      pill.className = "pill";
      $("#btn-pause").textContent = "Pause 5 min";
    }

    const dnssecPct = s.total ? (s.validated || 0) / s.total * 100 : 0;
    $("#stat-dnssec").textContent = `${dnssecPct.toFixed(0)}%`;
    $("#stat-history").textContent = d.history && d.history.enabled
      ? `history: ${d.history.days} day${d.history.days === 1 ? "" : "s"}, ${bytes(d.history.bytes)}`
      : "history off";

    const banner = $("#schedule-banner");
    const active = (d.schedules && d.schedules.active) || [];
    if (active.length) {
      banner.classList.remove("hidden");
      banner.innerHTML = active.map((a) => `⏰ <b>${esc(a.name)}</b> is active (${esc(a.start)}–${esc(a.end)}, ${esc(a.mode)}${a.group ? ", group " + esc(a.group) : ""})`).join("<br>");
    } else {
      banner.classList.add("hidden");
    }

    drawChart(s.timeline || []);
    fillMini("#top-blocked", s.top_blocked, "nothing blocked yet");
    fillMini("#top-clients", s.top_clients, "no devices yet");

    const rows = (d.upstreams || []).map((u) => `
      <tr>
        <td class="domain">${esc(u.name)}</td>
        <td><span class="tag ${u.healthy ? "allowed" : "blocked"}">${u.healthy ? "up" : "down"}</span></td>
        <td>${compact(u.queries)} q</td>
        <td>${u.avg_ms ? u.avg_ms.toFixed(0) + " ms" : "–"}</td>
      </tr>`).join("");
    $("#upstreams").innerHTML = rows || `<tr><td class="muted">no upstreams</td></tr>`;
  }

  function fillMini(sel, items, empty) {
    const el = $(sel);
    if (!items || !items.length) { el.innerHTML = `<tr><td class="muted">${empty}</td></tr>`; return; }
    el.innerHTML = items.map((i) => `<tr><td class="domain">${esc(i.name)}</td><td>${compact(i.count)}</td></tr>`).join("");
  }

  function drawChart(points) {
    const host = $("#chart");
    const w = Math.max(host.clientWidth, 320), h = 190, pad = 22;
    if (!points.length) { host.innerHTML = ""; return; }
    const max = Math.max(1, ...points.map((p) => p.total));
    const bw = (w - pad * 2) / points.length;
    let bars = "";
    points.forEach((p, i) => {
      const x = pad + i * bw;
      const th = ((h - pad * 2) * p.total) / max;
      const bh = ((h - pad * 2) * p.blocked) / max;
      const wd = Math.max(1, bw - 1.5);
      bars += `<rect x="${x.toFixed(1)}" y="${(h - pad - th).toFixed(1)}" width="${wd.toFixed(1)}" height="${th.toFixed(1)}" fill="#60a5fa" opacity=".55" rx="1.5"><title>${clock(p.time)} — ${p.total} queries, ${p.blocked} blocked</title></rect>`;
      if (bh > 0) bars += `<rect x="${x.toFixed(1)}" y="${(h - pad - bh).toFixed(1)}" width="${wd.toFixed(1)}" height="${bh.toFixed(1)}" fill="#f87171" rx="1.5"/>`;
    });
    const first = clock(points[0].time), last = clock(points[points.length - 1].time);
    host.innerHTML = `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
      <line x1="${pad}" y1="${h - pad}" x2="${w - pad}" y2="${h - pad}" stroke="#243057"/>
      ${bars}
      <text x="${pad}" y="${h - 6}" fill="#8d9ac4" font-size="11">${first}</text>
      <text x="${w - pad}" y="${h - 6}" fill="#8d9ac4" font-size="11" text-anchor="end">${last}</text>
      <text x="${pad}" y="14" fill="#8d9ac4" font-size="11">peak ${max}/10min</text>
    </svg>`;
  }

  /* ---------- query log ---------- */

  async function loadQueries() {
    const search = encodeURIComponent($("#q-search").value.trim());
    const status = $("#q-status").value;
    const d = await api(`/api/queries?limit=250&search=${search}&status=${status}`);
    const rows = (d.queries || []).map((q) => `
      <tr>
        <td class="muted">${clock(q.time)}</td>
        <td>${esc(q.device || q.client)}</td>
        <td class="domain">${esc(q.domain)}</td>
        <td class="muted">${esc(q.type)}</td>
        <td><span class="tag ${esc(q.status)}">${esc(q.status)}</span></td>
        <td class="muted">${esc(q.rule || q.source || q.upstream || "")}</td>
        <td class="muted">${(q.ms || 0).toFixed(1)}</td>
        <td><button class="btn tiny" data-quick="${q.status === "blocked" ? "allow" : "block"}" data-domain="${esc(q.domain)}">${q.status === "blocked" ? "allow" : "block"}</button></td>
      </tr>`).join("");
    $("#query-rows").innerHTML = rows || `<tr><td colspan="8" class="muted">no queries yet — point a device at this resolver</td></tr>`;
  }

  /* ---------- lists ---------- */

  async function loadLists() {
    const d = await api("/api/lists");
    $("#lists-total").textContent = `${compact(d.domains)} domains blocked in total`;
    $("#list-rows").innerHTML = (d.sources || []).map((s) => `
      <tr>
        <td><div>${esc(s.title)}</div><div class="hint domain">${esc(s.url)}</div></td>
        <td>${compact(s.domains)}</td>
        <td class="muted">${ago(s.last_updated)}</td>
        <td>${s.last_error ? `<span class="tag error">${esc(s.last_error)}</span>` : `<span class="tag allowed">ok</span>`}</td>
        <td><input type="checkbox" data-toggle="${esc(s.id)}" ${s.enabled ? "checked" : ""}></td>
        <td><button class="btn tiny danger" data-del-list="${esc(s.id)}">remove</button></td>
      </tr>`).join("") || `<tr><td colspan="6" class="muted">no lists configured</td></tr>`;
  }

  /* ---------- rules ---------- */

  async function loadRules() {
    const d = await api("/api/rules");
    $("#rule-rows").innerHTML = (d.rules || []).map((r) => `
      <tr>
        <td class="domain">${esc(r.pattern)}</td>
        <td><span class="tag ${r.action === "allow" ? "allowed" : "blocked"}">${esc(r.action)}</span></td>
        <td class="muted">${esc(r.group || "all devices")}</td>
        <td class="muted">${esc(r.comment || "")}</td>
        <td><button class="btn tiny danger" data-del-rule="${esc(r.pattern)}" data-action="${esc(r.action)}" data-group="${esc(r.group || "")}">remove</button></td>
      </tr>`).join("") || `<tr><td colspan="5" class="muted">no custom rules — lists are doing the work</td></tr>`;
  }

  /* ---------- devices ---------- */

  async function loadDevices() {
    const d = await api("/api/devices");
    $("#device-rows").innerHTML = (d.devices || []).map((v) => `
      <tr>
        <td class="domain">${esc(v.match)}</td>
        <td>${esc(v.name || "")}</td>
        <td class="muted">${esc(v.group || "default")}</td>
        <td>${v.paused ? `<span class="tag error">off</span>` : `<span class="tag allowed">on</span>`}</td>
        <td><button class="btn tiny danger" data-del-device="${esc(v.match)}">remove</button></td>
      </tr>`).join("") || `<tr><td colspan="5" class="muted">no named devices yet</td></tr>`;

    $("#seen-rows").innerHTML = (d.seen || []).map((v) => `
      <tr>
        <td class="domain">${esc(v.ip)}</td>
        <td>${esc(v.name || "")}</td>
        <td>${compact(v.queries)}</td>
        <td>${compact(v.blocked)}</td>
        <td class="muted">${ago(v.last_seen)}</td>
        <td><button class="btn tiny" data-adopt="${esc(v.ip)}">name it</button></td>
      </tr>`).join("") || `<tr><td colspan="6" class="muted">nothing has queried this resolver yet</td></tr>`;
  }

  /* ---------- device drill-down ---------- */

  let reportClient = "";

  async function loadReportClients() {
    const d = await api("/api/devices/clients?days=" + ($("#report-days").value || 7)).catch(() => null);
    if (!d || !d.enabled) return;
    const sel = $("#report-client");
    const current = sel.value;
    sel.innerHTML = `<option value="">pick a device…</option>` +
      (d.clients || []).map((c) => {
        const label = c.name ? `${c.name} (${c.client})` : c.client;
        return `<option value="${esc(c.client)}">${esc(label)} — ${compact(c.queries)}</option>`;
      }).join("");
    sel.value = current || reportClient || "";
  }

  async function loadDeviceReport() {
    if (!reportClient) {
      $("#report-body").classList.add("hidden");
      $("#report-empty").classList.remove("hidden");
      return;
    }
    const days = $("#report-days").value || 7;
    const d = await api(`/api/devices/report?client=${encodeURIComponent(reportClient)}&days=${days}`);
    if (!d.enabled) {
      $("#report-empty").textContent = d.error || "history is disabled";
      $("#report-empty").classList.remove("hidden");
      $("#report-body").classList.add("hidden");
      return;
    }
    const r = d.report || {};
    const p = d.policy || {};
    $("#report-empty").classList.add("hidden");
    $("#report-body").classList.remove("hidden");
    $("#rep-total").textContent = compact(r.total || 0);
    $("#rep-window").textContent = `last ${d.days} days`;
    $("#rep-blocked").textContent = compact(r.blocked || 0);
    $("#rep-ratio").textContent = `${(r.block_ratio || 0).toFixed(1)}% of its traffic`;
    $("#rep-cached").textContent = compact(r.cached || 0);
    $("#rep-latency").textContent = `${(r.avg_ms || 0).toFixed(1)} ms average`;
    $("#rep-policy").textContent = p.paused ? "unfiltered" : (p.group || "default");
    $("#rep-seen").textContent = r.last_seen ? `last seen ${ago(r.last_seen)}` : "";
    $("#rep-top").innerHTML = miniRows(r.top_domains);
    $("#rep-blocked-table").innerHTML = miniRows(r.top_blocked);
    drawHourly(r.hourly || [], r.blocked_hourly || []);
  }

  function miniRows(items) {
    if (!items || !items.length) return `<tr><td class="muted">nothing recorded</td></tr>`;
    return items.map((i) => `<tr><td class="domain">${esc(i.name)}</td><td class="num">${compact(i.count)}</td></tr>`).join("");
  }

  // drawHourly plots the device's day: total queries per UTC hour with the
  // blocked share on top, which makes "the TV phones home at 3am" obvious.
  function drawHourly(total, blocked) {
    const host = $("#rep-chart");
    if (!total.length) { host.innerHTML = ""; return; }
    const w = Math.max(host.clientWidth, 320), h = 150, pad = 22;
    const max = Math.max(1, ...total);
    const bw = (w - pad * 2) / total.length;
    let bars = "";
    total.forEach((v, i) => {
      const x = pad + i * bw;
      const th = ((h - pad * 2) * v) / max;
      const bh = ((h - pad * 2) * (blocked[i] || 0)) / max;
      const wd = Math.max(1, bw - 3);
      bars += `<rect x="${x.toFixed(1)}" y="${(h - pad - th).toFixed(1)}" width="${wd.toFixed(1)}" height="${th.toFixed(1)}" fill="#60a5fa" opacity=".5" rx="2"><title>${i}:00 UTC — ${v} queries, ${blocked[i] || 0} blocked</title></rect>`;
      if (bh > 0) bars += `<rect x="${x.toFixed(1)}" y="${(h - pad - bh).toFixed(1)}" width="${wd.toFixed(1)}" height="${bh.toFixed(1)}" fill="#f87171" rx="2"/>`;
    });
    host.innerHTML = `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
      <line x1="${pad}" y1="${h - pad}" x2="${w - pad}" y2="${h - pad}" stroke="#243057"/>
      ${bars}
      <text x="${pad}" y="${h - 6}" fill="#8d9ac4" font-size="11">00:00 UTC</text>
      <text x="${w - pad}" y="${h - 6}" fill="#8d9ac4" font-size="11" text-anchor="end">23:00 UTC</text>
      <text x="${pad}" y="14" fill="#8d9ac4" font-size="11">peak ${max}/hour</text>
    </svg>`;
  }

  /* ---------- settings ---------- */

  async function loadSettings() {
    const d = await api("/api/settings");
    const dns = d.dns || {};
    $("#settings-path").textContent = d.path ? `config: ${d.path}` : "";
    $("#set-sinkhole").value = dns.sinkhole || "zero-ip";
    $("#set-customv4").value = dns.custom_ipv4 || "";
    $("#set-upstreams").value = (dns.upstreams || []).join("\n");
    $("#set-doh").value = (dns.doh_upstreams || []).join("\n");
    $("#set-preferdoh").checked = !!dns.prefer_doh;
    $("#set-subdomains").checked = !!dns.block_subdomains;
    $("#set-cname").checked = !!dns.block_cname_cloaking;
    $("#set-https").checked = !!dns.block_https_records;
    $("#set-stale").checked = !!dns.serve_stale;
    $("#set-cachesize").value = dns.cache_size || 20000;
    $("#set-timeout").value = dns.upstream_timeout_ms || 3500;
    $("#set-blockttl").value = dns.block_ttl == null ? 60 : dns.block_ttl;
    $("#set-allowed").value = (dns.allowed_clients || []).join("\n");
    $("#set-interval").value = (d.lists && d.lists.update_interval_hours) || 24;
    $("#set-dnssec").checked = !!dns.request_dnssec;
    $("#set-doh-server").checked = !!dns.doh_server;
    $("#set-forward").value = (dns.conditional_forward || []).map((f) => `${f.domain}=${f.upstream}`).join("\n");
    const web = d.web || {};
    const tls = web.tls || {};
    $("#set-prefetch").checked = !!dns.prefetch;
    $("#set-tls").checked = !!tls.enabled;
    $("#set-tls-port").value = tls.port || 8443;
    $("#set-tls-redirect").checked = !!tls.redirect_http;
    window.__dns = dns;
    window.__web = web;
    loadSecurityState();
  }

  async function loadSecurityState() {
    const d = await api("/api/sessions").catch(() => null);
    if (!d) return;
    const bits = [];
    bits.push(d.password_set ? "password set" : "no password — the dashboard is open");
    if (d.token_set) bits.push("API token set");
    bits.push(d.tls ? "HTTPS on" : "HTTP only");
    bits.push(`${d.sessions} active session${d.sessions === 1 ? "" : "s"}`);
    if (d.fingerprint) bits.push(`cert ${d.fingerprint.slice(0, 17)}…`);
    $("#security-state").textContent = bits.join(" · ");
  }

  const lines = (sel) => $(sel).value.split("\n").map((s) => s.trim()).filter(Boolean);

  /* ---------- history ---------- */

  let historyOffset = 0;
  const HISTORY_PAGE = 100;

  async function loadHistory() {
    const params = new URLSearchParams({
      limit: String(HISTORY_PAGE),
      offset: String(historyOffset),
      search: $("#h-search").value.trim(),
      status: $("#h-status").value,
    });
    if ($("#h-from").value) params.set("from", $("#h-from").value);
    if ($("#h-to").value) params.set("to", $("#h-to").value + "T23:59:59Z");

    const d = await api("/api/history?" + params.toString());
    if (!d.enabled) {
      $("#history-rows").innerHTML = `<tr><td colspan="7" class="muted">history is disabled in settings</td></tr>`;
      $("#history-meta").textContent = "";
      return;
    }
    $("#history-meta").textContent = `${fmt.format(d.total)} matching · ${d.days.length} day${d.days.length === 1 ? "" : "s"} kept · ${bytes(d.bytes)} on disk`;
    $("#h-page").textContent = d.total
      ? `${historyOffset + 1}–${Math.min(historyOffset + HISTORY_PAGE, d.total)} of ${fmt.format(d.total)}`
      : "no matches";
    $("#h-export").href = "/api/history/export" + ($("#h-from").value ? `?from=${$("#h-from").value}` : "");

    $("#history-rows").innerHTML = (d.records || []).map((q) => `
      <tr>
        <td class="muted">${new Date(q.time).toLocaleString([], { hour12: false })}</td>
        <td>${esc(q.device || q.client)}</td>
        <td class="domain">${esc(q.domain)}</td>
        <td class="muted">${esc(q.type)}</td>
        <td><span class="tag ${esc(q.status)}">${esc(q.status)}</span></td>
        <td class="muted">${esc(q.rule || q.source || q.upstream || "")}</td>
        <td class="muted">${(q.ms || 0).toFixed(1)}</td>
      </tr>`).join("") || `<tr><td colspan="7" class="muted">nothing matches that search</td></tr>`;

    const daily = await api("/api/history/daily?days=30");
    drawDaily(daily.days || []);
  }

  function drawDaily(days) {
    const host = $("#history-chart");
    if (!days.length) { host.innerHTML = ""; return; }
    const w = Math.max(host.clientWidth, 320), h = 160, pad = 24;
    const max = Math.max(1, ...days.map((d) => d.total));
    const bw = (w - pad * 2) / days.length;
    let bars = "";
    days.forEach((d, i) => {
      const x = pad + i * bw;
      const th = ((h - pad * 2) * d.total) / max;
      const bh = ((h - pad * 2) * d.blocked) / max;
      const wd = Math.max(1, bw - 3);
      bars += `<rect x="${x.toFixed(1)}" y="${(h - pad - th).toFixed(1)}" width="${wd.toFixed(1)}" height="${th.toFixed(1)}" fill="#60a5fa" opacity=".5" rx="2"><title>${d.day}: ${d.total} queries, ${d.blocked} blocked</title></rect>`;
      if (bh > 0) bars += `<rect x="${x.toFixed(1)}" y="${(h - pad - bh).toFixed(1)}" width="${wd.toFixed(1)}" height="${bh.toFixed(1)}" fill="#f87171" rx="2"/>`;
    });
    host.innerHTML = `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
      <line x1="${pad}" y1="${h - pad}" x2="${w - pad}" y2="${h - pad}" stroke="#243057"/>
      ${bars}
      <text x="${pad}" y="${h - 6}" fill="#8d9ac4" font-size="11">${days[0].day}</text>
      <text x="${w - pad}" y="${h - 6}" fill="#8d9ac4" font-size="11" text-anchor="end">${days[days.length - 1].day}</text>
      <text x="${pad}" y="14" fill="#8d9ac4" font-size="11">peak ${max}/day</text>
    </svg>`;
  }

  /* ---------- schedules ---------- */

  async function loadSchedules() {
    const d = await api("/api/schedules");
    const activeIDs = new Set((d.active || []).map((a) => a.id));
    $("#sc-next").textContent = d.next_change ? `next change at ${clock(d.next_change)}` : "";
    $("#schedule-rows").innerHTML = (d.schedules || []).map((s) => `
      <tr>
        <td>${esc(s.name)}</td>
        <td class="muted">${esc(s.start)}–${esc(s.end)}</td>
        <td class="muted">${esc((s.days || []).join(", ") || "every day")}</td>
        <td class="muted">${esc(s.group || "all devices")}</td>
        <td class="muted">${esc(s.mode)}</td>
        <td>${activeIDs.has(s.id) ? `<span class="tag blocked">active now</span>` : (s.enabled ? `<span class="tag allowed">armed</span>` : `<span class="tag error">off</span>`)}</td>
        <td>
          <button class="btn tiny" data-toggle-schedule="${esc(s.id)}">${s.enabled ? "disable" : "enable"}</button>
          <button class="btn tiny danger" data-del-schedule="${esc(s.id)}">remove</button>
        </td>
      </tr>`).join("") || `<tr><td colspan="7" class="muted">no schedules yet — try a 22:00–07:00 bedtime for the kids' group</td></tr>`;
    window.__schedules = d.schedules || [];
  }

  /* ---------- dhcp ---------- */

  async function loadDHCP() {
    const d = await api("/api/dhcp");
    const c = d.config || {};
    $("#dh-enabled").checked = !!c.enabled;
    $("#dh-server").value = c.server_ip || "";
    $("#dh-gateway").value = c.gateway || "";
    $("#dh-netmask").value = c.netmask || "255.255.255.0";
    $("#dh-start").value = c.range_start || "";
    $("#dh-end").value = c.range_end || "";
    $("#dh-lease").value = c.lease_hours || 12;
    $("#dh-domain").value = c.domain_name || "";
    $("#dhcp-count").textContent = `${(d.leases || []).length} known client${(d.leases || []).length === 1 ? "" : "s"}`;
    $("#lease-rows").innerHTML = (d.leases || []).map((l) => `
      <tr>
        <td class="domain">${esc(l.ip)}</td>
        <td>${esc(l.hostname || "")}</td>
        <td class="muted domain">${esc(l.mac)}</td>
        <td class="muted">${esc(l.vendor || "")}</td>
        <td class="muted">${l.static ? "reserved" : ago(l.expires)}</td>
        <td>
          <button class="btn tiny" data-pin-mac="${esc(l.mac)}" data-pin-ip="${esc(l.ip)}" data-pin-host="${esc(l.hostname || "")}">pin</button>
          ${l.static ? `<button class="btn tiny danger" data-unpin="${esc(l.mac)}">unpin</button>` : ""}
        </td>
      </tr>`).join("") || `<tr><td colspan="6" class="muted">no leases yet — enable DHCP above and turn your router's server off</td></tr>`;
  }

  /* ---------- tabs & refresh ---------- */

  const loaders = {
    overview: loadSummary,
    queries: loadQueries,
    history: loadHistory,
    schedules: loadSchedules,
    dhcp: loadDHCP,
    lists: loadLists,
    rules: loadRules,
    devices: async () => { await loadDevices(); await loadReportClients(); await loadDeviceReport(); },
    settings: loadSettings,
  };

  async function refresh() {
    try {
      await loaders[activeTab]();
      if (activeTab !== "overview") await loadSummary().catch(() => {});
    } catch (e) {
      if (e.message !== "unauthorized") console.error(e);
    }
  }

  function schedule() {
    clearInterval(timer);
    const live = $("#q-live").checked;
    const every = activeTab === "queries" ? (live ? 2000 : 0) : 5000;
    if (every) timer = setInterval(refresh, every);
  }

  function selectTab(name) {
    activeTab = name;
    $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
    $$(".panel").forEach((p) => p.classList.toggle("active", p.id === "tab-" + name));
    refresh();
    schedule();
  }

  /* ---------- events ---------- */

  $$(".tab").forEach((t) => t.addEventListener("click", () => selectTab(t.dataset.tab)));
  $("#q-live").addEventListener("change", schedule);
  $("#q-search").addEventListener("input", () => loadQueries().catch(() => {}));
  $("#q-status").addEventListener("change", () => loadQueries().catch(() => {}));
  window.addEventListener("resize", () => { if (activeTab === "overview") refresh(); });

  $("#btn-pause").addEventListener("click", async () => {
    const paused = $("#status-pill").classList.contains("paused");
    await api("/api/control", { method: "POST", body: JSON.stringify({ action: paused ? "resume" : "pause", minutes: 5 }) });
    toast(paused ? "Filtering resumed" : "Filtering paused for 5 minutes");
    refresh();
  });

  $("#btn-update").addEventListener("click", async (e) => {
    e.target.disabled = true; e.target.textContent = "Updating…";
    try {
      const d = await api("/api/lists/update", { method: "POST" });
      toast(`Lists updated — ${fmt.format(d.domains)} domains`);
    } catch (err) { toast("Update failed: " + err.message, true); }
    e.target.disabled = false; e.target.textContent = "Update lists";
    refresh();
  });

  $("#btn-flush").addEventListener("click", async () => {
    const d = await api("/api/control", { method: "POST", body: JSON.stringify({ action: "flush-cache" }) });
    toast(`Cache flushed (${d.flushed} entries)`);
    refresh();
  });

  $("#check-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const domain = $("#check-domain").value.trim();
    if (!domain) return;
    const d = await api(`/api/check?domain=${encodeURIComponent(domain)}`);
    const dec = d.decision || {};
    $("#check-result").innerHTML = dec.blocked
      ? `<span class="verdict blocked">BLOCKED</span> — matched <code>${esc(dec.rule)}</code> from <b>${esc(dec.source)}</b>
         <button class="btn tiny" data-quick="allow" data-domain="${esc(d.domain)}">allow it</button>`
      : `<span class="verdict allowed">ALLOWED</span> — no list or rule matches
         <button class="btn tiny" data-quick="block" data-domain="${esc(d.domain)}">block it</button>`;
  });

  $("#list-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api("/api/lists", { method: "POST", body: JSON.stringify({ title: $("#list-title").value.trim(), url: $("#list-url").value.trim() }) });
      $("#list-title").value = ""; $("#list-url").value = "";
      toast("List added — downloading in the background");
      loadLists();
    } catch (err) { toast(err.message, true); }
  });

  $("#rule-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api("/api/rules", { method: "POST", body: JSON.stringify({
        pattern: $("#rule-pattern").value.trim(),
        action: $("#rule-action").value,
        group: $("#rule-group").value.trim(),
        comment: $("#rule-comment").value.trim(),
      })});
      $("#rule-pattern").value = ""; $("#rule-comment").value = "";
      toast("Rule saved");
      loadRules();
    } catch (err) { toast(err.message, true); }
  });

  $("#device-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api("/api/devices", { method: "POST", body: JSON.stringify({
        match: $("#device-match").value.trim(),
        name: $("#device-name").value.trim(),
        group: $("#device-group").value.trim(),
        paused: $("#device-paused").checked,
      })});
      $("#device-match").value = ""; $("#device-name").value = "";
      toast("Device saved");
      loadDevices();
    } catch (err) { toast(err.message, true); }
  });

  $("#settings-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const dns = Object.assign({}, window.__dns || {}, {
      sinkhole: $("#set-sinkhole").value,
      custom_ipv4: $("#set-customv4").value.trim(),
      upstreams: lines("#set-upstreams"),
      doh_upstreams: lines("#set-doh"),
      prefer_doh: $("#set-preferdoh").checked,
      block_subdomains: $("#set-subdomains").checked,
      block_cname_cloaking: $("#set-cname").checked,
      block_https_records: $("#set-https").checked,
      serve_stale: $("#set-stale").checked,
      cache_size: Number($("#set-cachesize").value),
      upstream_timeout_ms: Number($("#set-timeout").value),
      block_ttl: Number($("#set-blockttl").value),
      allowed_clients: lines("#set-allowed"),
      request_dnssec: $("#set-dnssec").checked,
      prefetch: $("#set-prefetch").checked,
      doh_server: $("#set-doh-server").checked,
      conditional_forward: lines("#set-forward").map((l) => {
        const [domain, upstream] = l.split("=");
        return { domain: (domain || "").trim(), upstream: (upstream || "").trim() };
      }).filter((f) => f.domain && f.upstream),
    });
    try {
      await api("/api/settings", { method: "PUT", body: JSON.stringify({ dns, update_interval_hours: Number($("#set-interval").value) }) });
      toast("Settings saved");
      loadSettings();
    } catch (err) { toast(err.message, true); }
  });

  $("#btn-reset-stats").addEventListener("click", async () => {
    await api("/api/control", { method: "POST", body: JSON.stringify({ action: "reset-stats" }) });
    toast("Statistics reset");
    refresh();
  });

  // Delegated clicks for table buttons.
  document.addEventListener("click", async (e) => {
    const t = e.target;
    if (!(t instanceof HTMLElement)) return;
    try {
      if (t.dataset.quick) {
        await api("/api/rules", { method: "POST", body: JSON.stringify({
          pattern: t.dataset.domain, action: t.dataset.quick, comment: "added from dashboard",
        })});
        toast(`${t.dataset.domain} will now be ${t.dataset.quick === "allow" ? "allowed" : "blocked"}`);
        refresh();
      } else if (t.dataset.delList) {
        await api(`/api/lists?id=${encodeURIComponent(t.dataset.delList)}`, { method: "DELETE" });
        toast("List removed"); loadLists();
      } else if (t.dataset.delRule) {
        await api(`/api/rules?pattern=${encodeURIComponent(t.dataset.delRule)}&action=${t.dataset.action}&group=${encodeURIComponent(t.dataset.group || "")}`, { method: "DELETE" });
        toast("Rule removed"); loadRules();
      } else if (t.dataset.delDevice) {
        await api(`/api/devices?match=${encodeURIComponent(t.dataset.delDevice)}`, { method: "DELETE" });
        toast("Device removed"); loadDevices();
      } else if (t.dataset.delSchedule) {
        await api(`/api/schedules?id=${encodeURIComponent(t.dataset.delSchedule)}`, { method: "DELETE" });
        toast("Schedule removed"); loadSchedules();
      } else if (t.dataset.toggleSchedule) {
        const sc = (window.__schedules || []).find((x) => x.id === t.dataset.toggleSchedule);
        if (sc) {
          await api("/api/schedules", { method: "POST", body: JSON.stringify({ ...sc, enabled: !sc.enabled }) });
          toast(sc.enabled ? "Schedule disabled" : "Schedule enabled");
          loadSchedules();
        }
      } else if (t.dataset.pinMac) {
        await api("/api/dhcp/reservation", { method: "POST", body: JSON.stringify({
          mac: t.dataset.pinMac, ip: t.dataset.pinIp, hostname: t.dataset.pinHost,
        })});
        toast("Address pinned"); loadDHCP();
      } else if (t.dataset.unpin) {
        await api(`/api/dhcp/reservation?mac=${encodeURIComponent(t.dataset.unpin)}`, { method: "DELETE" });
        toast("Reservation removed"); loadDHCP();
      } else if (t.dataset.adopt) {
        selectTab("devices");
        $("#device-match").value = t.dataset.adopt;
        $("#device-name").focus();
      }
    } catch (err) { toast(err.message, true); }
  });

  document.addEventListener("change", async (e) => {
    const t = e.target;
    if (t instanceof HTMLInputElement && t.dataset.toggle) {
      try {
        const d = await api("/api/lists/toggle", { method: "POST", body: JSON.stringify({ id: t.dataset.toggle, enabled: t.checked }) });
        toast(`${fmt.format(d.domains)} domains active`);
      } catch (err) { toast(err.message, true); }
    }
  });

  $("#history-form").addEventListener("submit", (e) => {
    e.preventDefault();
    historyOffset = 0;
    loadHistory().catch((err) => toast(err.message, true));
  });
  $("#h-prev").addEventListener("click", () => {
    historyOffset = Math.max(0, historyOffset - HISTORY_PAGE);
    loadHistory().catch(() => {});
  });
  $("#h-next").addEventListener("click", () => {
    historyOffset += HISTORY_PAGE;
    loadHistory().catch(() => {});
  });

  $("#schedule-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const days = $("#sc-days").value.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
    try {
      await api("/api/schedules", { method: "POST", body: JSON.stringify({
        name: $("#sc-name").value.trim(),
        group: $("#sc-group").value.trim(),
        mode: $("#sc-mode").value,
        days,
        start: $("#sc-start").value,
        end: $("#sc-end").value,
        enabled: true,
        patterns: $("#sc-patterns").value.split("\n").map((s) => s.trim()).filter(Boolean),
      })});
      $("#sc-name").value = ""; $("#sc-patterns").value = "";
      toast("Schedule saved");
      loadSchedules();
    } catch (err) { toast(err.message, true); }
  });

  $("#dhcp-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const d = await api("/api/dhcp", { method: "POST", body: JSON.stringify({
        enabled: $("#dh-enabled").checked,
        server_ip: $("#dh-server").value.trim(),
        gateway: $("#dh-gateway").value.trim(),
        netmask: $("#dh-netmask").value.trim(),
        range_start: $("#dh-start").value.trim(),
        range_end: $("#dh-end").value.trim(),
        lease_hours: Number($("#dh-lease").value),
        domain_name: $("#dh-domain").value.trim(),
      })});
      toast(d.restart_required ? "Saved — restart adblockerpro to apply" : "DHCP settings saved");
      loadDHCP();
    } catch (err) { toast(err.message, true); }
  });

  $("#reservation-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api("/api/dhcp/reservation", { method: "POST", body: JSON.stringify({
        mac: $("#res-mac").value.trim(),
        ip: $("#res-ip").value.trim(),
        hostname: $("#res-host").value.trim(),
      })});
      $("#res-mac").value = ""; $("#res-ip").value = ""; $("#res-host").value = "";
      toast("Address pinned");
      loadDHCP();
    } catch (err) { toast(err.message, true); }
  });

  $("#restore-file").addEventListener("change", async (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    try {
      const d = await api("/api/restore", { method: "POST", body: await file.text() });
      toast(`Restored ${d.rules} rules, ${d.devices} devices, ${d.schedules} schedules`);
      refresh();
    } catch (err) { toast(err.message, true); }
    e.target.value = "";
  });

  /* ---------- device report controls ---------- */

  $("#report-client").addEventListener("change", (e) => {
    reportClient = e.target.value;
    loadDeviceReport().catch((err) => toast(err.message, true));
  });
  $("#report-days").addEventListener("change", () => {
    loadReportClients().then(loadDeviceReport).catch(() => {});
  });

  /* ---------- security ---------- */

  $("#password-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = $("#password-msg");
    msg.textContent = "";
    const next = $("#pw-new").value;
    if (next && next !== $("#pw-repeat").value) {
      msg.textContent = "the two new passwords do not match";
      return;
    }
    try {
      // Web settings first, so a failed password change does not lose them.
      const web = Object.assign({}, window.__web || {}, {
        tls: {
          enabled: $("#set-tls").checked,
          port: Number($("#set-tls-port").value) || 8443,
          redirect_http: $("#set-tls-redirect").checked,
          cert_file: (window.__web && window.__web.tls && window.__web.tls.cert_file) || "",
          key_file: (window.__web && window.__web.tls && window.__web.tls.key_file) || "",
        },
      });
      await api("/api/settings", { method: "PUT", body: JSON.stringify({ web }) });
      if (next || $("#pw-current").value) {
        await api("/api/password", {
          method: "POST",
          body: JSON.stringify({ current: $("#pw-current").value, new: next }),
        });
        $("#pw-current").value = $("#pw-new").value = $("#pw-repeat").value = "";
        toast(next ? "Password updated — other sessions signed out" : "Password cleared");
      } else {
        toast("Security settings saved");
      }
      if ($("#set-tls").checked) {
        msg.textContent = "HTTPS takes effect after a restart: sudo systemctl restart adblockerpro";
      }
      loadSettings();
    } catch (err) { msg.textContent = err.message; }
  });

  $("#btn-logout").addEventListener("click", async () => {
    await fetch("/api/logout", { method: "POST", credentials: "same-origin" });
    location.reload();
  });

  $("#btn-logout-all").addEventListener("click", async () => {
    try {
      await api("/api/sessions", { method: "DELETE" });
      location.reload();
    } catch (err) { toast(err.message, true); }
  });

  $("#login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const res = await fetch("/api/login", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: $("#login-token").value, token: $("#login-token").value }),
      });
      if (res.status === 429) throw new Error("too many attempts — wait a few minutes");
      if (!res.ok) throw new Error("that password was not accepted");
      $("#login").classList.add("hidden");
      $("#login-error").textContent = "";
      refresh();
    } catch (err) { $("#login-error").textContent = err.message; }
  });

  selectTab("overview");
})();
