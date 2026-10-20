#!/usr/bin/env bash
# Install or update secwatch as a systemd service (no Docker needed).
# Run as root from the unpacked source directory:  bash deploy/install.sh
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP=/opt/secwatch/app
VENV=/opt/secwatch/venv
ENV_FILE=/etc/secwatch/secwatch.env

if ! python3 -c "import ensurepip" 2>/dev/null; then
  apt-get install -y python3-venv
fi

id secwatch >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin secwatch
usermod -a -G adm secwatch

install -d -m 0755 /opt/secwatch
rm -rf "$APP.new"
install -d -m 0755 "$APP.new"
cp -r "$SRC/secwatch" "$SRC/requirements.txt" "$APP.new/"
[ -d "$VENV" ] || python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --disable-pip-version-check -r "$APP.new/requirements.txt"
rm -rf "$APP" && mv "$APP.new" "$APP"
chown -R root:root /opt/secwatch
cat > /usr/local/bin/secwatch <<'WRAPPER'
#!/bin/sh
# secwatch CLI: setup, doctor (the service itself runs via systemd).
cd /opt/secwatch/app && exec /opt/secwatch/venv/bin/python -m secwatch "$@"
WRAPPER
chmod 0755 /usr/local/bin/secwatch

install -d -m 0750 -o root -g secwatch /etc/secwatch
FIRST_INSTALL=0
if [ ! -f "$ENV_FILE" ]; then
  FIRST_INSTALL=1
  umask 027
  {
    echo "SECWATCH_WEB_USER=admin"
    echo "SECWATCH_WEB_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
    echo "SECWATCH_TIMEZONE=$(timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"
    echo "SECWATCH_SYSLOG_TZ=$(timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"
  } > "$ENV_FILE"
  chown root:secwatch "$ENV_FILE"
  chmod 0640 "$ENV_FILE"
fi

install -m 0644 "$SRC/deploy/secwatch.service" /etc/systemd/system/secwatch.service
systemctl daemon-reload
systemctl enable --quiet secwatch
systemctl restart secwatch
sleep 3
systemctl is-active secwatch
if [ "$FIRST_INSTALL" = 1 ]; then
  echo
  echo "Installed. Finish the setup (logs, Telegram, Supabase) and check it:"
  echo "  sudo secwatch setup"
  echo "  sudo systemctl restart secwatch"
  echo "  sudo secwatch doctor"
fi
