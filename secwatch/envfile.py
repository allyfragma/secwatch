"""Read and update the KEY=value settings file (/etc/secwatch/secwatch.env or .env).

Updates keep comments, order and unrelated keys; the file is replaced
atomically with owner-only (or owner+group) permissions.
"""

from __future__ import annotations

import os
import re
import tempfile

DEFAULT_PATHS = ("/etc/secwatch/secwatch.env", ".env")
_LINE = re.compile(r"^\s*([A-Z][A-Z0-9_]*)\s*=(.*)$")


def find_env_file(explicit: str | None = None) -> str:
    if explicit:
        return explicit
    for path in DEFAULT_PATHS:
        if os.path.exists(path):
            return path
    return DEFAULT_PATHS[0] if os.geteuid() == 0 else DEFAULT_PATHS[1]


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def read_env(path: str) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                m = _LINE.match(line)
                if m:
                    values[m.group(1)] = _unquote(m.group(2))
    except FileNotFoundError:
        pass
    return values


def load_into_environ(path: str) -> None:
    """Make a manually started CLI see the same settings as the service."""
    for key, value in read_env(path).items():
        os.environ.setdefault(key, value)


def _check_value(key: str, value: str) -> None:
    if "\n" in value or "\r" in value:
        raise ValueError(f"{key}: value must be a single line")


def update_env(path: str, updates: dict[str, str | None], mode: int = 0o640, group: str | None = "secwatch") -> None:
    """Set (or with None remove) keys, keeping everything else as is."""
    for key, value in updates.items():
        if value is not None:
            _check_value(key, value)
    lines: list[str] = []
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        pass
    pending = dict(updates)
    out: list[str] = []
    for line in lines:
        m = _LINE.match(line)
        if m and m.group(1) in pending:
            value = pending.pop(m.group(1))
            if value is not None:
                out.append(f"{m.group(1)}={value}")
            continue
        out.append(line)
    out += [f"{k}={v}" for k, v in pending.items() if v is not None]

    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".secwatch-env-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
        os.chmod(tmp, mode)
        if group and os.geteuid() == 0:
            import grp
            try:
                os.chown(tmp, 0, grp.getgrnam(group).gr_gid)
            except KeyError:
                os.chmod(tmp, mode & 0o700)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
