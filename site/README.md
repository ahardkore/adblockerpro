# The adblockerpro website

Four static pages, no build step, no dependencies. Open `index.html` in a
browser and it works; push it anywhere that serves files.

```
index.html      landing page — what it does, honest expectations
hardware.html   the shopping list (reads products.json)
setup.html      the eight-step walkthrough
faq.html        troubleshooting and questions
products.json   ← the only file you need to edit
```

## Adding your Amazon affiliate links

Open `products.json`:

1. Put your Associates tag in `"affiliate_tag"`, e.g. `"yourtag-20"`. It is
   appended automatically to every `amazon.*` URL that does not already have
   one, so you can paste plain product links.
2. Fill in the `"url"` of each product. An empty `url` renders a greyed-out
   "link coming soon" button instead of a dead link, so a half-finished list
   still looks deliberate.
3. Edit `"price"` as free text (`"about $45"`) — vague prices do not go stale.
4. Add or remove products and kits freely; `kits[].items` is a list of
   product `id`s.

Affiliate links are rendered with `rel="nofollow sponsored noopener"` and the
disclosure line from `products.json` is printed under every kit, which is what
the Amazon Associates operating agreement and the FTC both expect.

## Publishing

`.github/workflows/pages.yml` deploys this folder to GitHub Pages on every
push to `main`. Turn it on once: repository **Settings → Pages → Source:
GitHub Actions**. Any static host (Netlify, Cloudflare Pages, S3) works just
as well — point it at `site/`.

## Previewing locally

```bash
python3 -m http.server 8081 --directory site
```
