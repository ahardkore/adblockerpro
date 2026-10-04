/* adblockerpro website — shared behaviour. No dependencies. */
(() => {
  "use strict";

  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  /* ---------- basic accessibility ---------- */

  const firstSection = $("body > section");
  if (firstSection) {
    firstSection.id = firstSection.id || "main-content";
    const skip = document.createElement("a");
    skip.className = "skip-link";
    skip.href = `#${firstSection.id}`;
    skip.textContent = "Skip to content";
    document.body.prepend(skip);
  }

  /* ---------- copy buttons on every code block ---------- */

  $$("pre").forEach((pre) => {
    const btn = document.createElement("button");
    btn.className = "copy";
    btn.type = "button";
    btn.textContent = "copy";
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(pre.innerText.replace(/\ncopy$/, "").trim());
        btn.textContent = "copied";
      } catch (_) {
        btn.textContent = "select it by hand";
      }
      setTimeout(() => (btn.textContent = "copy"), 1800);
    });
    pre.appendChild(btn);
  });

  /* ---------- highlight the current page in the nav ---------- */

  const here = location.pathname.split("/").pop() || "index.html";
  $$(".site-nav a").forEach((a) => {
    if ((a.getAttribute("href") || "").split("/").pop() === here) a.classList.add("current");
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
