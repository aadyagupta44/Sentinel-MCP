# Deploying the demo on Hugging Face Spaces (free, no card, 24/7)

This runs the **entire** Sentinel stack — MCP server + self-hosted Keycloak +
Postgres + Redis + OPA — inside a single Hugging Face Space, in demo mode
(simulated data, everything else real). Free, no credit card, always reachable
(sleeps when idle, wakes on the next visit in ~2 minutes).

The files for this live in [`huggingface/`](../huggingface/). The Dockerfile
clones your app from GitHub at build time, so your GitHub repo must be public
and up to date first.

---

## Phase 0 — Prerequisites
- Your repo pushed to GitHub (public). Note the URL and branch (default `main`).
- A free **Hugging Face** account — https://huggingface.co/join (no card).

## Phase 1 — Create the Space
1. https://huggingface.co/new-space
2. **Space name:** e.g. `sentinel-mcp`
3. **SDK:** choose **Docker** → **Blank**.
4. **Hardware:** the free **CPU basic** tier is fine.
5. Create it. Note your Space host — it looks like `youruser-sentinel-mcp.hf.space`.

## Phase 2 — Push the container files into the Space
A Space is its own git repo. Put the contents of `huggingface/` at its **root**:

```bash
git clone https://huggingface.co/spaces/<youruser>/sentinel-mcp hf-space
cd hf-space

# copy the Space files from your project's huggingface/ folder
cp /path/to/sentinel-soc/huggingface/Dockerfile        .
cp /path/to/sentinel-soc/huggingface/Caddyfile         .
cp /path/to/sentinel-soc/huggingface/supervisord.conf  .
cp /path/to/sentinel-soc/huggingface/entrypoint.sh     .
cp /path/to/sentinel-soc/huggingface/README.md         .

git add -A && git commit -m "Sentinel MCP demo" && git push
```

> If your GitHub repo/branch differs from the default, edit the two `ARG` lines
> at the top of the `Dockerfile` (`REPO_URL`, `REPO_REF`) before pushing.

## Phase 3 — (Optional) set the Keycloak admin password
Space → **Settings → Variables and secrets** → add a **secret**:
- `KC_ADMIN_PASSWORD` = a strong value (defaults to `admin` if unset).

## Phase 4 — Wait for the build + first boot
- The **build** takes ~10–15 min the first time (it downloads Java, Keycloak,
  Postgres, and builds the app).
- First **boot** takes ~2–3 min (Postgres init + Keycloak realm import).
- Watch the **Logs** tab. You're up when you see the app log `sentinel_starting`
  and Caddy is serving.

## Phase 5 — Verify
Open your Space URL (`https://<youruser>-sentinel-mcp.hf.space`):
- `/` → the terminal landing page, health line shows **operational**
- `/health` → `{"status":"ok",...}`
- `/.well-known/mcp` → the MCP manifest

## Phase 6 — Connect Claude Desktop
1. **Settings → Connectors → Add custom connector**
2. URL: `https://<youruser>-sentinel-mcp.hf.space/mcp`
3. Log in as `analyst` / `analyst123` or `senior` / `senior123`.
4. Test the role boundary (analyst denied write, senior allowed).

---

## Known iteration points (expect to touch these once)
Because this is a single-container cram, a couple of things commonly need a
nudge on first deploy — send me the **Logs** tab output and I'll pinpoint it:

1. **Postgres init** — if the app keeps restarting with connection errors, the
   cluster may still be initialising; it should self-heal within a minute. If
   not, the `PGBIN` path detection in `entrypoint.sh` may need the exact
   Postgres version.
2. **Keycloak OAuth handshake** — if Claude's login fails on the redirect, open
   `https://<space>/admin` (user `admin`), realm `sentinel` → Clients →
   `claude-desktop`, and confirm the redirect URI Claude used is allowed. The
   realm already permits `https://*.hf.space/*` and `https://claude.ai/*`.
   If Claude uses **dynamic client registration** instead of the fixed client,
   enable client registration in the realm (or we switch to a pre-registered
   client id) — tell me what the log shows.
3. **Cold start** — the first request after idle returns slowly (~2 min) while
   Keycloak boots. This is expected on free hardware.

## Updating later
Push changes to GitHub, then in the Space: **Settings → Factory reboot**
(rebuilds and re-clones the latest code).
