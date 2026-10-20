# Security policy

secwatch reads server logs and, optionally, holds a Telegram bot token and a
Supabase access token. Please report vulnerabilities privately:

- GitHub: **Security → Report a vulnerability** on this repository (private advisory).

Please do not open public issues for security problems. You will get an answer
within a few days.

## Design rules the code follows

- Read-only: the monitor never changes the host, firewall or Supabase project.
- Secrets live only in the settings file (mode 0640 root:secwatch) and are never
  logged, printed or sent anywhere except the API they belong to.
- The dashboard listens on 127.0.0.1 and requires a password; open it through
  an SSH tunnel.
- A Supabase token of a read-only organization member is enough.
