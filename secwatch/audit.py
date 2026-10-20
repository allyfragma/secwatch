"""Read-only checks of the host configuration (mounted under SECWATCH_HOST_ROOT)."""

from __future__ import annotations

import glob
import os
import re

from .config import Settings
from .models import Finding, catalog_finding

SSHD_DEFAULTS = {
    "passwordauthentication": "yes",
    "permitrootlogin": "prohibit-password",
    "permitemptypasswords": "no",
    "maxauthtries": "6",
    "x11forwarding": "no",
    "port": "22",
}


def read_sshd_config(settings: Settings, path: str = "/etc/ssh/sshd_config") -> dict[str, str] | None:
    """Effective global sshd options: first value wins, Include is followed,
    everything after the first Match block is ignored (it is conditional)."""
    main = settings.host_path(path)
    if not os.path.exists(main):
        return None
    values: dict[str, str] = {}
    stop = False

    def load(file_path: str, depth: int = 0) -> None:
        nonlocal stop
        if depth > 8 or stop:
            return
        try:
            with open(file_path, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            return
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"\s+|=", line, maxsplit=1)
            key = parts[0].lower()
            value = parts[1].strip() if len(parts) > 1 else ""
            if key == "match":
                stop = True
                return
            if key == "include":
                for pattern in value.split():
                    if not pattern.startswith("/"):
                        pattern = "/etc/ssh/" + pattern
                    for inc in sorted(glob.glob(settings.host_path(pattern))):
                        load(inc, depth + 1)
                        if stop:
                            return
                continue
            values.setdefault(key, value.split()[0].lower() if key != "allowusers" else value)

    load(main)
    return values


def audit_host(settings: Settings) -> list[Finding]:
    findings: list[Finding] = []
    cfg = read_sshd_config(settings)
    if cfg is None:
        findings.append(catalog_finding("sshd_config_missing", "info"))
    else:
        eff = {**SSHD_DEFAULTS, **cfg}
        if eff["permitemptypasswords"] == "yes":
            findings.append(catalog_finding("ssh_empty_passwords", "critical"))
        # Keyboard-interactive (PAM) also accepts passwords, but only count it when set explicitly:
        # Ubuntu ships "KbdInteractiveAuthentication no" in sshd_config.
        kbd = cfg.get("kbdinteractiveauthentication", cfg.get("challengeresponseauthentication", "no"))
        if eff["passwordauthentication"] == "yes" or kbd == "yes":
            findings.append(catalog_finding("ssh_password_auth", "high"))
        if eff["permitrootlogin"] == "yes":
            findings.append(catalog_finding("ssh_root_password", "high"))
        elif eff["permitrootlogin"] in ("prohibit-password", "without-password"):
            findings.append(catalog_finding("ssh_root_key", "info"))
        try:
            if int(eff["maxauthtries"]) > 4:
                findings.append(catalog_finding("ssh_maxauthtries", "low", value=eff["maxauthtries"]))
        except ValueError:
            pass
        if eff["x11forwarding"] == "yes":
            findings.append(catalog_finding("ssh_x11", "low"))

    if not os.path.isdir(settings.host_path("/etc/fail2ban")):
        findings.append(catalog_finding("no_fail2ban", "medium"))
    ufw = settings.host_path("/etc/ufw/ufw.conf")
    if os.path.exists(ufw):
        with open(ufw, encoding="utf-8", errors="replace") as fh:
            enabled = re.search(r"^\s*ENABLED\s*=\s*yes", fh.read(), re.M | re.I)
        if not enabled:
            findings.append(catalog_finding("ufw_disabled", "medium"))
    return findings
