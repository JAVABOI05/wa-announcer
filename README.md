# WhatsApp Dual-Group Announcement Relay Service

Resilient single-tenant web relay that broadcasts text, media, voice notes, and interactive polls to two WhatsApp groups from one account.

**Version 1.1** — kill-switch fix, reconnect, CSRF, rate-limited login, SQLite sessions, persistent dedup, health endpoint, graceful shutdown.

## Stack

- **Runtime:** Node.js 20+ LTS / TypeScript (ES2022, NodeNext, ESM)
- **WhatsApp:** whatsapp-web.js + LocalAuth + headless Chromium
- **HTTP:** Express + helmet + express-rate-limit + CSRF tokens
- **Sessions:** SQLite-backed (survives restarts)
- **DB:** better-sqlite3 (WAL) — jobs, logs, digests, sessions
- **Scheduler:** node-cron (every minute)
- **Process:** PM2 recommended

## Quick start

```bash
cd wa-announcer
cp .env.example .env
# Edit .env: ADMIN_PASSWORD + SESSION_SECRET (64-char hex)

npm install --registry https://registry.npmjs.org/
npm run build
node dist/server.js
```

1. Scan the QR code (WhatsApp → Linked Devices).
2. Copy two group IDs from the discovery log into `.env`.
3. Restart the process.
4. Open `http://localhost:3000` and log in.

### Production (PM2)

```bash
pm2 start dist/server.js --name "wa-relay" --max-memory-restart 500M
pm2 startup && pm2 save
```

### Remote access (Cloudflare Tunnel)

```bash
cloudflared tunnel --url http://localhost:3000

# Production .env:
# TRUST_PROXY=true
# SECURE_COOKIE=true
```

### Health check

```bash
curl -s http://localhost:3000/health
```

## Features

- Dual-group sequential dispatch with 3.5–6.5 s inter-group jitter
- Typing / recording presence simulation before every send
- Auto-reconnect on WhatsApp disconnect (backoff)
- Offline / kill-switch messages auto-queue as PENDING jobs
- Native WhatsApp polls (single / multi-answer)
- Media + optional voice-note flag
- Pin mapped to WhatsApp-allowed durations (24h / 7d / 30d)
- Emergency kill-switch (soft pause; jobs stay PENDING; BLOCKED logged once)
- Cancel pending jobs + upload cleanup
- Constant-time password compare + login rate limit (5 / 15 min)
- CSRF tokens on all mutating forms
- 24h persistent message digests (dedup across restarts)
- Structured logging (`LOG_LEVEL`)
- Graceful SIGTERM/SIGINT shutdown

## Backup (recommended)

```bash
cp relay_data.sqlite relay_data.sqlite.bak
tar czf wwebjs_auth_backup.tgz .wwebjs_auth
```

## API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | No | Liveness / readiness JSON |
| GET | `/login` | No | Login form |
| POST | `/login` | No (rate-limited) | Authenticate |
| POST | `/logout` | Yes + CSRF | Destroy session |
| GET | `/` | Yes | Admin dashboard |
| POST | `/api/broadcast` | Yes + CSRF | Text / media |
| POST | `/api/poll` | Yes + CSRF | Interactive poll |
| POST | `/api/cancel-job` | Yes + CSRF | Cancel scheduled job |
| POST | `/api/toggle-switch` | Yes + CSRF | Emergency pause on/off |

## Deployment notes

### Not suitable for Vercel (or other serverless)

This service is a **long-running daemon**: it keeps a headless Chromium session
(via `whatsapp-web.js` / Puppeteer), writes to SQLite on disk, and runs a
minute-by-minute cron worker. Vercel Functions are short-lived and ephemeral —
they cannot host this architecture.

**Supported hosts:** a VPS or always-on machine with Node 20+, PM2, and enough
RAM for Chromium (~500 MB restart ceiling is configured in the runbook).

Expose the admin UI with Cloudflare Tunnel (or similar), not by deploying the
bot process to Vercel.

### Disclaimer

Unofficial. Not affiliated with WhatsApp or Meta. Automation may violate
WhatsApp Terms of Service and can result in account restriction. Use at your
own risk, preferably for low-volume internal announcements only.
