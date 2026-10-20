# secwatch — see who attacks your server and what to fix

A small, free monitor for a Linux server (and optionally your Supabase project).
It reads your logs **read-only**, counts today's attacks, shows where they come
from and what they target, rates the risk, tells you **exactly what to fix**
(with copy-paste commands) and sends the important things to Telegram.

Made for people who ship apps fast and do not want to become security engineers.

> secwatch watches and explains; it does not block. Pair it with fail2ban or
> CrowdSec for automatic bans — secwatch shows what they do.

[Русская версия](README.ru.md)

## What it sees

| Source | What you get |
|---|---|
| `/var/log/auth.log` (sshd, incl. `sshd-session` of OpenSSH 9.8+) | password and username guessing, aborted logins, port scans, **successful logins** (new IP / after brute force) |
| nginx `access.log`, Caddy JSON log | probes for `.env`, `.git`, `wp-admin`…, exploit attempts (path traversal, SQL injection, Log4Shell, command injection), scanners, junk requests, **secret files actually served** |
| `fail2ban.log` | who was banned and when |
| `/etc/ssh`, `/etc/fail2ban`, `/etc/ufw` | config check: password login, root login, MaxAuthTries, X11, fail2ban and firewall present |
| Supabase Management API (optional) | Security Advisor findings, failed Auth logins and rate limits |

The dashboard (password protected) shows a risk score, today's counters, a
**"What to fix"** list, attacks by hour and over 7 days, attacking IPs with
country and network, targets, guessed usernames and SSH logins.

Telegram alerts: SSH login from a new IP, a secret file served, an attack spike
from one IP, new critical findings, and a daily digest. No repeats, and the
first run becomes the baseline — no alert storm on install.

Privacy: query strings of web requests are dropped; tokens and keys are never
stored or logged. Country/ASN lookups are offline.

## Install (Ubuntu / Debian, one command)

```bash
curl -fsSL https://raw.githubusercontent.com/allyfragma/secwatch/main/install.sh | sudo bash
```

It installs what is missing (Python venv), downloads the latest release,
**verifies its checksum**, sets up a systemd service running as an
unprivileged user, starts the setup wizard and finally runs `secwatch doctor`.

- Update: run the same command again (settings and data are kept).
- Specific version: `… | sudo bash -s -- --version v0.2.0`
- Remove: `… | sudo bash -s -- --uninstall` (add `--purge` to delete settings and data too).
- Later: `sudo secwatch setup` to change settings, `sudo secwatch doctor` to check everything.

Prefer to read the script first? `curl -fsSLO …/install.sh && less install.sh && sudo bash install.sh`.

`secwatch setup` asks only for what it cannot find itself:

- **Language**: `en` or `ru`.
- **Telegram**: create a **new** bot in @BotFather and paste its token. Then
  send `/start` to the bot — the chat is detected automatically and a test
  message is sent.
- **Supabase** (optional): a personal access token (a read-only member's token
  is enough; set an expiry) and the project ref.

Open the dashboard through an SSH tunnel (it listens on 127.0.0.1 only):

```bash
ssh -L 8088:127.0.0.1:8088 root@your-server   # then http://localhost:8088
```

The user is `admin`; the password is in `/etc/secwatch/secwatch.env`
(`sudo grep PASSWORD /etc/secwatch/secwatch.env`).

### Docker

```bash
mkdir secwatch && cd secwatch
curl -fsSLO https://raw.githubusercontent.com/allyfragma/secwatch/main/compose.yaml
sudo docker compose run --rm setup     # wizard: writes ./.env
sudo docker compose up -d
sudo docker compose exec secwatch python -m secwatch doctor
```

Image: `ghcr.io/allyfragma/secwatch` (amd64 and arm64).

The container runs as non-root on a read-only filesystem without
capabilities; host logs are mounted read-only (group `adm`).

### Try it on sample data

```bash
docker compose -f compose.dev.yaml up --build   # http://localhost:8089  admin / dev-password
docker build --target test -t secwatch:test . && docker run --rm secwatch:test
```

## Settings

All settings are environment variables (see [.env.example](.env.example));
`secwatch setup` writes them for you. Useful ones:

| Variable | Default | |
|---|---|---|
| `SECWATCH_LANG` | `en` | `en` or `ru` for the dashboard and alerts |
| `SECWATCH_TIMEZONE` | `UTC` | timezone for "today" |
| `SECWATCH_TELEGRAM_TOKEN` / `_CHAT_ID` | — | direct Telegram alerts |
| `SECWATCH_SUPABASE_TOKEN` / `_PROJECT_REF` | — | Supabase checks |
| `SECWATCH_GEOIP_AUTO_UPDATE` | `1` | download country/ASN databases automatically |
| `SECWATCH_ERP_INGEST_URL` / `_KEY` | — | send alerts and summaries to your own app over HTTP instead of Telegram |

Country and network come from the free [DB-IP Lite](https://db-ip.com/db/lite.php)
databases (CC BY 4.0, no account), downloaded into the data directory and
refreshed monthly. MaxMind `GeoLite2-Country.mmdb` / `GeoLite2-ASN.mmdb` in the
data directory take precedence.

No `/var/log/auth.log` (journald only, e.g. Debian 12)? `sudo apt install rsyslog`.

## How it works

`parsers.py` parses log lines, `collector.py` reads logs incrementally
(rotation-aware), `audit.py` checks host config, `supabase.py` talks to the
Supabase Management API, `summary.py` builds the risk score and
recommendations, `alerts.py` sends alerts, `web.py` + `templates/` serve the
dashboard, `worker.py` runs the loop. Data lives in SQLite.

## Roadmap

- Supabase-only mode as a GitHub Action (for apps without their own server).
- "Fix with AI": export findings (no secrets) as a ready prompt for Claude Code / Cursor.
- journald and CrowdSec as sources.

## License

MIT. IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0).
Security issues: see [SECURITY.md](SECURITY.md).
