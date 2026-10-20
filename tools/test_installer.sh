#!/usr/bin/env bash
# End-to-end check of install.sh in fresh distro containers (systemd is faked).
#   bash tools/test_installer.sh [image ...]      default: ubuntu:24.04 ubuntu:22.04 debian:12
set -euo pipefail
cd "$(dirname "$0")/.."
images=("$@")
[ ${#images[@]} -gt 0 ] || images=(ubuntu:24.04 ubuntu:22.04 debian:12)

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git archive --format=tar.gz --prefix=secwatch-test/ -o "$tmp/secwatch.tar.gz" HEAD

cat > "$tmp/run.sh" <<'INNER'
set -euo pipefail
# Fake systemd: the installer only needs these calls to succeed.
mkdir -p /run/systemd/system /var/lib/secwatch
printf '#!/bin/sh\n[ "$1" = is-active ] && echo active\nexit 0\n' > /usr/local/bin/systemctl
chmod +x /usr/local/bin/systemctl
mkdir -p /var/log
echo "2026-10-20T10:00:00+00:00 host sshd[1]: Invalid user test from 203.0.113.9 port 1" > /var/log/auth.log
chgrp adm /var/log/auth.log && chmod 640 /var/log/auth.log

echo "--- install"
bash /work/install.sh --source /work/secwatch.tar.gz --no-setup > /tmp/install.log 2>&1 || { cat /tmp/install.log; exit 1; }
secwatch --version
grep -q "^SECWATCH_WEB_PASSWORD=.\{20,\}" /etc/secwatch/secwatch.env
[ "$(stat -c '%a %U:%G' /etc/secwatch/secwatch.env)" = "640 root:secwatch" ]
pw1="$(grep ^SECWATCH_WEB_PASSWORD= /etc/secwatch/secwatch.env)"

echo "--- service starts and serves"
chown secwatch /var/lib/secwatch
( set -a; . /etc/secwatch/secwatch.env; set +a
  export SECWATCH_HOST_ROOT=/ SECWATCH_DB=/var/lib/secwatch/secwatch.db SECWATCH_WEB_HOST=127.0.0.1 SECWATCH_GEOIP_AUTO_UPDATE=0
  cd /opt/secwatch/app && exec runuser -u secwatch -- /opt/secwatch/venv/bin/python -m secwatch run ) > /tmp/run.log 2>&1 &
for _ in $(seq 1 30); do python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8088/healthz", timeout=1)' 2>/dev/null && break; sleep 1; done
python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8088/healthz", timeout=2)' || { cat /tmp/run.log; exit 1; }
sleep 2
secwatch doctor | sed 's/^/    /'
secwatch doctor >/dev/null   # exit code 0 = no failures

echo "--- update keeps settings"
bash /work/install.sh --source /work/secwatch.tar.gz --no-setup > /tmp/update.log 2>&1 || { cat /tmp/update.log; exit 1; }
[ "$(grep ^SECWATCH_WEB_PASSWORD= /etc/secwatch/secwatch.env)" = "$pw1" ]

echo "--- uninstall --purge"
bash /work/install.sh --uninstall --purge
[ ! -e /opt/secwatch ] && [ ! -e /etc/secwatch ] && [ ! -e /usr/local/bin/secwatch ] && ! id secwatch 2>/dev/null
echo "PASS"
INNER

for image in "${images[@]}"; do
  echo "===== $image"
  MSYS_NO_PATHCONV=1 docker run --rm \
    -v "$(cd "$tmp" && pwd -W 2>/dev/null || pwd):/work-src:ro" \
    -v "$(pwd -W 2>/dev/null || pwd)/install.sh:/work/install.sh:ro" \
    "$image" bash -c 'mkdir -p /work && cp /work-src/secwatch.tar.gz /work-src/run.sh /work/ && bash /work/run.sh'
done
