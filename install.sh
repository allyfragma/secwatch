#!/usr/bin/env bash
# secwatch one-line installer (Ubuntu / Debian with systemd).
#
#   curl -fsSL https://raw.githubusercontent.com/allyfragma/secwatch/main/install.sh | sudo bash
#
# Run the same command again to update (settings and data are kept).
# Options (after `bash -s --`):
#   --version vX.Y.Z   install a specific release (default: latest release)
#   --no-setup         do not start the setup wizard
#   --source PATH      install from a local source directory or .tar.gz (offline/testing)
#   --uninstall        remove the service and program (keeps settings and data)
#   --purge            with --uninstall: also delete settings, data and the system user
set -euo pipefail

REPO="${SECWATCH_REPO:-allyfragma/secwatch}"
SW_VERSION="${SECWATCH_VERSION:-latest}"
SOURCE=""
RUN_SETUP=1
UNINSTALL=0
PURGE=0
ENV_FILE=/etc/secwatch/secwatch.env
# Some networks drop connections to GitHub now and then: retry instead of failing.
CURL_RETRY=(--connect-timeout 15 --retry 4 --retry-delay 2 --retry-all-errors)

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
fail() { printf '\033[31mError:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) SW_VERSION="${2:?--version needs a value}"; shift 2 ;;
    --no-setup) RUN_SETUP=0; shift ;;
    --source) SOURCE="${2:?--source needs a path}"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) sed -n '2,13p' "$0" 2>/dev/null || true; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || fail "run as root: curl -fsSL … | sudo bash"

if [ "$UNINSTALL" -eq 1 ]; then
  systemctl disable --now secwatch 2>/dev/null || true
  rm -f /etc/systemd/system/secwatch.service /usr/local/bin/secwatch
  systemctl daemon-reload 2>/dev/null || true
  rm -rf /opt/secwatch
  if [ "$PURGE" -eq 1 ]; then
    rm -rf /etc/secwatch /var/lib/secwatch
    id secwatch >/dev/null 2>&1 && userdel secwatch
    say "secwatch removed with its settings and data."
  else
    say "secwatch removed. Settings (/etc/secwatch) and data (/var/lib/secwatch) were kept; add --purge to delete them."
  fi
  exit 0
fi

# --- platform -------------------------------------------------------------
# Read the OS id in a subshell: /etc/os-release defines its own VERSION and other variables.
# shellcheck disable=SC1091
os_ids="$(. /etc/os-release 2>/dev/null && echo " ${ID:-} ${ID_LIKE:-} ")" || fail "cannot read /etc/os-release"
case "$os_ids" in
  *" debian "*|*" ubuntu "*) ;;
  *) fail "this installer supports Ubuntu and Debian. Elsewhere use Docker (see README)." ;;
esac
[ -d /run/systemd/system ] || fail "systemd is not running here. Use Docker instead (see README)."

missing=""
command -v python3 >/dev/null 2>&1 || missing="$missing python3"
python3 -c 'import ensurepip' >/dev/null 2>&1 || missing="$missing python3-venv"
command -v curl >/dev/null 2>&1 || missing="$missing curl"
command -v tar >/dev/null 2>&1 || missing="$missing tar"
[ -e /etc/ssl/certs/ca-certificates.crt ] || missing="$missing ca-certificates"
if [ -n "$missing" ]; then
  say "Installing:$missing"
  apt-get update -qq
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $missing >/dev/null
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' \
  || fail "Python 3.10 or newer is needed (found $(python3 -V 2>&1)). Use Docker on older systems."

# --- source ---------------------------------------------------------------
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -n "$SOURCE" ]; then
  if [ -d "$SOURCE" ]; then
    cp -r "$SOURCE" "$WORK/src"
  else
    mkdir "$WORK/src" && tar -xzf "$SOURCE" -C "$WORK/src" --strip-components=1
  fi
  say "Installing secwatch from $SOURCE"
else
  if [ "$SW_VERSION" = "latest" ]; then
    # The release page redirects to .../releases/tag/<version>. This avoids api.github.com
    # (rate limits, and some hosts cannot reach it over IPv6).
    latest_url="$(curl -fsSL "${CURL_RETRY[@]}" -o /dev/null -w '%{url_effective}' \
      "https://github.com/$REPO/releases/latest")" || fail "cannot reach github.com to find the latest release"
    SW_VERSION="${latest_url##*/}"
    case "$SW_VERSION" in v[0-9]*) ;; *) fail "cannot find the latest release of $REPO" ;; esac
  fi
  case "$SW_VERSION" in v*) ;; *) SW_VERSION="v$SW_VERSION" ;; esac
  case "$SW_VERSION" in *[!A-Za-z0-9._-]*) fail "invalid version: $SW_VERSION" ;; esac
  base="https://github.com/$REPO/releases/download/$SW_VERSION"
  archive="secwatch-$SW_VERSION.tar.gz"
  say "Downloading secwatch $SW_VERSION"
  curl -fsSL "${CURL_RETRY[@]}" -o "$WORK/$archive" "$base/$archive" || fail "download failed: $base/$archive"
  curl -fsSL "${CURL_RETRY[@]}" -o "$WORK/SHA256SUMS" "$base/SHA256SUMS" || fail "download failed: $base/SHA256SUMS"
  (cd "$WORK" && grep " $archive\$" SHA256SUMS | sha256sum -c --quiet -) \
    || fail "checksum mismatch: the download is damaged or was tampered with"
  mkdir "$WORK/src" && tar -xzf "$WORK/$archive" -C "$WORK/src" --strip-components=1
fi

[ -f "$WORK/src/deploy/install.sh" ] || fail "not a secwatch source tree"

FIRST_INSTALL=1
[ -f "$ENV_FILE" ] && FIRST_INSTALL=0

bash "$WORK/src/deploy/install.sh" >/dev/null
say "secwatch $(secwatch --version 2>/dev/null | awk '{print $2}') is installed and running."

# --- first run --------------------------------------------------------------
# stdin is the piped script, so the wizard talks to the terminal directly.
if [ "$FIRST_INSTALL" -eq 1 ] && [ "$RUN_SETUP" -eq 1 ] && { : </dev/tty; } 2>/dev/null; then
  echo
  if secwatch setup </dev/tty >/dev/tty; then
    systemctl restart secwatch
  fi
elif [ "$FIRST_INSTALL" -eq 1 ]; then
  echo
  say "Next: sudo secwatch setup && sudo systemctl restart secwatch"
fi

echo
secwatch doctor || true
echo
echo "Dashboard: ssh -L 8088:127.0.0.1:8088 root@<this-server>  then  http://localhost:8088"
echo "Login: admin / password: sudo grep PASSWORD $ENV_FILE"
echo "Update: run the same install command again.  Remove: … | sudo bash -s -- --uninstall"
