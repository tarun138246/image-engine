# Pratima Image Engine — Server Setup

## 1. Prerequisites

| Dependency | Required? | Purpose |
|---|---|---|
| Node.js 18+ | Yes | Runs the server |
| Redis | Yes | Distributed upload concurrency semaphore |
| ClamAV (`clamd`) | Optional | Malware scanning — uploads proceed without it, just unscanned |
| Ghostscript (`gs`) | Optional | PDF compression — PDFs still upload without it, just uncompressed |
| nginx (or similar) | Recommended | TLS termination + reverse proxy in front of Node |

Install on Debian/Ubuntu:
```bash
sudo apt update
sudo apt install -y nodejs npm redis-server clamav-daemon ghostscript
sudo systemctl enable --now redis-server clamav-daemon
sudo freshclam   # update virus definitions before first use
```

## 2. Fresh install

```bash
git clone <your-repo-url> pratima && cd pratima
npm install
cp .env.example .env
```

Edit `.env`:
- `API_KEY` — random string, used as the admin key (dashboard + company management)
- `ENCRYPTION_KEY` — generate with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
- `STORAGE_PATH` — absolute path with room for uploads, e.g. `/var/pratima`
- `PUBLIC_URL` — the public base URL images/PDFs will be served from, e.g. `https://pratima.elatecrunchies.com`
- `REDIS_URL` — include a password if your Redis instance requires one
- Leave `GS_BINARY`, `CLAMD_SOCKET`, `MAX_FILE_SIZE`, `MAX_BACKUP_SIZE` at their defaults unless you have a reason to change them

```bash
mkdir -p /var/pratima && sudo chown $(whoami) /var/pratima
node pratima.js       # sanity-check it boots, then Ctrl+C
```

## 3. Run it as a service (systemd)

`/etc/systemd/system/pratima.service`:
```ini
[Unit]
Description=Pratima Image Engine
After=network.target redis-server.service

[Service]
Type=simple
WorkingDirectory=/opt/pratima
EnvironmentFile=/opt/pratima/.env
ExecStart=/usr/bin/node pratima.js
Restart=on-failure
User=pratima

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pratima
```

Put nginx in front for TLS (`proxy_pass http://127.0.0.1:3001;`), and point `PUBLIC_URL` at the
public hostname nginx terminates.

## 4. Upgrading an already-running server (this PDF/domain/backup update)

This update only **adds** capability — it does not change or migrate anything already stored.
Existing images keep working at their existing URLs untouched, exactly as before.

```bash
cd /opt/pratima
git pull
npm install            # pulls in the new adm-zip dependency — required, the server won't start without it
sudo systemctl restart pratima
```

That's it. No data migration, no re-uploading, no changes to existing company records or files.
- Companies keep working unrestricted (open to any domain) until you explicitly set an allow-list.
- PDF upload/compression and backup/restore are new endpoints — nothing existing calls them, so
  nothing breaks if you never use them.
- If Ghostscript isn't installed, PDFs still upload fine, just without compression (check the
  "Ghostscript" status tile on the dashboard).

## 5. What's new

- **PDF uploads**: `POST /upload` now also accepts `application/pdf` via the same `image` field —
  malware-scanned, optionally Ghostscript-compressed, encrypted at rest, served back with the right
  `Content-Type`.
- **Per-company domain restriction**: dashboard → Companies tab → "Domains" button, or
  `PUT /companies/:id/domains`. See `api-docs.md` for details and caveats (Referer-based, so it's
  best-effort against browsers that strip referrers).
- **Backup / restore (per company)**: dashboard → Companies tab → "Backup" / "Restore" buttons, or
  `GET /companies/:id/backup` / `POST /companies/:id/restore`. Restore only replaces file contents,
  never the company's live API key.

Full endpoint details: see `api-docs.md`.
