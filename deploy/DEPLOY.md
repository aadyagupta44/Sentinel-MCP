# Deploying the Sentinel MCP Demo (Setup 2)

This stands up the **public demo**: the full server running for real (OAuth,
roles, policy, rate limiting, audit) with simulated tool data (`DEMO_MODE=true`).
It runs free and always-on on an Oracle Cloud "Always Free" VM.

**Result:** `https://<your-domain>` (landing page + MCP endpoint) and
`https://id.<your-domain>` (Keycloak login), connectable from Claude Desktop.

---

## What you need (once)

- An **Oracle Cloud "Always Free"** account (free forever; a credit card is used
  for identity verification only, not charged).
- A free **DuckDNS** subdomain (https://www.duckdns.org) — e.g. `sentinel-soc`.

---

## Phase 0 — Provision the VM

1. Oracle Cloud → **Compute → Instances → Create instance**.
2. Image/shape: **Ubuntu 22.04**, shape **VM.Standard.A1.Flex** (Ampere/ARM),
   set **2 OCPU / 12 GB** (well within Always Free: 4 OCPU / 24 GB).
   - If you see *"Out of host capacity"*, try another Availability Domain or
     region, or retry later — this is the one common Oracle friction point.
3. Add your SSH public key, create, and note the **public IP**.
4. **Networking → open ports 80 and 443:**
   - In the VCN's **Security List**, add Ingress rules: source `0.0.0.0/0`,
     TCP ports **80** and **443**.
   - On the VM itself, Ubuntu's iptables may block them — run:
     ```bash
     sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT
     sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT
     sudo netfilter-persistent save
     ```

## Phase 1 — Point DuckDNS at the VM

1. On duckdns.org, create a subdomain (e.g. `sentinel-soc`) and set its IP to the
   VM's public IP. `sentinel-soc.duckdns.org` **and** `id.sentinel-soc.duckdns.org`
   now both resolve to your VM (DuckDNS answers wildcards).
2. Verify from your laptop: `ping sentinel-soc.duckdns.org` shows the VM IP.

## Phase 2 — Install Docker on the VM

```bash
ssh ubuntu@<vm-public-ip>
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-plugin git
sudo usermod -aG docker $USER && newgrp docker
```

## Phase 3 — Deploy

```bash
git clone <your-repo-url> sentinel && cd sentinel

cp .env.prod.example .env.prod
nano .env.prod          # set DOMAIN + two passwords (openssl rand -base64 24)

docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

Watch it come up (Keycloak takes ~60–90s to import the realm the first time):

```bash
docker compose -f docker-compose.prod.yml logs -f sentinel keycloak caddy
```

## Phase 4 — Verify it's live

From your laptop:

```bash
curl https://<your-domain>/health                       # {"status":"ok",...}
curl https://<your-domain>/.well-known/mcp               # MCP manifest
curl https://id.<your-domain>/realms/sentinel/.well-known/openid-configuration
```

Open `https://<your-domain>` in a browser → the landing page. Caddy fetches TLS
certificates automatically on first request (give it ~30s).

## Phase 5 — Prove it end-to-end in Claude Desktop

1. Claude Desktop → **Settings → Connectors → Add custom connector**.
2. URL: `https://<your-domain>/mcp`.
3. It opens a browser to Keycloak — log in as a demo user:

   | user     | password    | role            |
   |----------|-------------|-----------------|
   | `analyst`| `analyst123`| analyst (read)  |
   | `senior` | `senior123` | senior_analyst  |

4. The `sentinel` tools appear. Try the role boundary:
   - As **analyst**: *"Isolate host LAPTOP-HR-03"* → **denied** (needs senior).
   - As **senior**: same request → **allowed**, and written to the audit log.

> If Claude shows a specific OAuth **redirect URI** during the connect step and
> Keycloak rejects it, add that exact URI to the `claude-desktop` client in the
> Keycloak admin console (`https://id.<your-domain>` → realm `sentinel` →
> Clients → claude-desktop → Valid redirect URIs), then retry. This is the one
> integration point that can need a tweak per Claude version.

---

## Updating

```bash
git pull
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

## Costs & footprint

Everything here is within Oracle's Always Free allowance. The stack uses ~2 GB
RAM (no OpenSearch/Wazuh — those are only needed for live data). Nothing expires.
