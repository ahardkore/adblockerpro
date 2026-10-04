/* adblockerpro website — shared behaviour. No dependencies. */
(() => {
  "use strict";

  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  /* ---------- theme toggle (dark ⇄ light, remembered) ---------- */

  const root = document.documentElement;
  const themeBtn = $("#theme-toggle");

  function paintTheme() {
    const light = root.getAttribute("data-theme") === "light";
    if (!themeBtn) return;
    const ico = $(".theme-ico", themeBtn);
    if (ico) ico.textContent = light ? "☀️" : "🌙";
    themeBtn.title = light ? "Switch to dark theme" : "Switch to light theme";
    themeBtn.setAttribute("aria-label", themeBtn.title);
  }

  if (themeBtn) {
    paintTheme();
    themeBtn.addEventListener("click", () => {
      const next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("abp-theme", next); } catch (_) {}
      paintTheme();
    });
    const preference = window.matchMedia("(prefers-color-scheme: light)");
    preference.addEventListener("change", (event) => {
      try {
        if (localStorage.getItem("abp-theme")) return;
      } catch (_) { return; }
      root.setAttribute("data-theme", event.matches ? "light" : "dark");
      paintTheme();
    });
  }

  /* ---------- mobile navigation ---------- */

  const navBtn = $("#nav-toggle");
  const nav = $("#site-nav");
  const mobile = window.matchMedia("(max-width: 880px)");

  function syncNav() {
    if (!nav || !navBtn) return;
    if (mobile.matches) {
      const open = navBtn.getAttribute("aria-expanded") === "true";
      nav.hidden = !open;
      navBtn.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    } else {
      nav.hidden = false;
      navBtn.setAttribute("aria-expanded", "false");
      navBtn.setAttribute("aria-label", "Open menu");
    }
  }

  if (navBtn && nav) {
    navBtn.addEventListener("click", () => {
      navBtn.setAttribute(
        "aria-expanded",
        navBtn.getAttribute("aria-expanded") === "true" ? "false" : "true"
      );
      syncNav();
    });
    nav.addEventListener("click", (e) => {
      if (e.target.tagName === "A" && mobile.matches) {
        navBtn.setAttribute("aria-expanded", "false");
        syncNav();
      }
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && mobile.matches && navBtn.getAttribute("aria-expanded") === "true") {
        navBtn.setAttribute("aria-expanded", "false");
        syncNav();
        navBtn.focus();
      }
    });
    document.addEventListener("click", (e) => {
      if (mobile.matches && navBtn.getAttribute("aria-expanded") === "true" &&
          !nav.contains(e.target) && !navBtn.contains(e.target)) {
        navBtn.setAttribute("aria-expanded", "false");
        syncNav();
      }
    });
    mobile.addEventListener("change", syncNav);
    syncNav();
  }

  /* ---------- copy buttons on every code block ---------- */

  const copyStatus = document.createElement("span");
  copyStatus.className = "visually-hidden";
  copyStatus.setAttribute("aria-live", "polite");
  document.body.appendChild(copyStatus);

  $$("pre").forEach((pre) => {
    const btn = document.createElement("button");
    btn.className = "copy";
    btn.type = "button";
    btn.textContent = "copy";
    btn.setAttribute("aria-label", "Copy code");
    btn.addEventListener("click", async () => {
      try {
        const code = $("code", pre);
        await navigator.clipboard.writeText((code ? code.textContent : pre.textContent).trim());
        btn.textContent = "copied";
        copyStatus.textContent = "Code copied to clipboard";
      } catch (_) {
        btn.textContent = "select it by hand";
        copyStatus.textContent = "Could not copy automatically; select the code manually";
      }
      setTimeout(() => (btn.textContent = "copy"), 1800);
    });
    pre.appendChild(btn);
  });

  /* ---------- highlight the current page in the nav ---------- */

  const here = location.pathname.split("/").pop() || "index.html";
  $$(".site-nav a").forEach((a) => {
    if ((a.getAttribute("href") || "").split("/").pop() === here) {
      a.classList.add("current");
      a.setAttribute("aria-current", "page");
    }
  });

  /* ---------- responsive data tables ---------- */

  $$("table.compare").forEach((table) => {
    const labels = $$("thead th", table).map((th) => th.textContent.trim());
    if (!labels.length) return;
    table.classList.add("responsive");
    $$("tbody tr", table).forEach((row) => {
      $$("td", row).forEach((cell, index) => cell.dataset.label = labels[index] || "");
    });
  });

  /* ---------- shopping list ---------- */

  const shop = $("#shop");
  if (!shop) return;

  // affiliate(url) appends the Associates tag when the owner has set one and
  // the link does not already carry its own.
  function affiliate(url, tag) {
    if (!url) return "";
    if (!tag) return url;
    try {
      const u = new URL(url);
      if (!/amazon\./i.test(u.hostname)) return url;
      if (!u.searchParams.has("tag")) u.searchParams.set("tag", tag);
      return u.toString();
    } catch (_) {
      return url;
    }
  }

  function productCard(p, tag) {
    const link = affiliate(p.url, tag);
    const buy = link
      ? `<a class="btn primary small" href="${esc(link)}" target="_blank" rel="nofollow sponsored noopener">View on Amazon</a>`
      : `<span class="btn small disabled">link coming soon</span>`;
    return `
      <div class="product">
        <div>
          <h3>${esc(p.name)}</h3>
          <p class="why">${esc(p.why)}</p>
          ${p.watch ? `<p class="watch">Watch out: ${esc(p.watch)}</p>` : ""}
        </div>
        <div class="buy">
          ${buy}
          <span class="price">${esc(p.price || "")}</span>
        </div>
      </div>`;
  }

  fetch("products.json")
    .then((r) => r.json())
    .then((data) => {
      const byId = Object.fromEntries((data.products || []).map((p) => [p.id, p]));
      const kits = data.kits || [];
      const tag = data.affiliate_tag || "";
      let active = kits.length ? kits[0].id : "";

      function render() {
        const kit = kits.find((k) => k.id === active) || kits[0];
        if (!kit) return;
        shop.innerHTML = `
          <div class="kit-tabs">
            ${kits.map((k) => `<button class="kit-tab ${k.id === active ? "on" : ""}" data-kit="${esc(k.id)}">${esc(k.title)}</button>`).join("")}
          </div>
          <p class="kit-blurb">${esc(kit.blurb)}</p>
          ${(kit.items || []).map((id) => byId[id] ? productCard(byId[id], tag) : "").join("")}
          <div class="kit-total">Total: ${esc(kit.total || "")}</div>
          <p class="disclosure">${esc(data.disclosure || "")}</p>
          <p class="disclosure">Already own a spare Pi, a card and a power supply? You need nothing else — skip straight to
            <a href="setup.html">the setup guide</a>.</p>`;
        $$(".kit-tab", shop).forEach((b) =>
          b.addEventListener("click", () => { active = b.dataset.kit; render(); }));
      }
      render();
    })
    .catch(() => {
      shop.innerHTML = `<p class="disclosure">Could not load the shopping list. See
        <a href="https://github.com/ahardkore/adblockerpro">the repository</a> for the hardware notes.</p>`;
    });
})();
