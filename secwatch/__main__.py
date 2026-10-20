import argparse
import logging
import os
import sys

from . import __version__, db, i18n
from .config import Settings

# Same values as Environment= in deploy/secwatch.service.
SERVICE_DEFAULTS = {"SECWATCH_HOST_ROOT": "/", "SECWATCH_DB": "/var/lib/secwatch/secwatch.db",
                    "SECWATCH_WEB_HOST": "127.0.0.1"}


def serve() -> None:
    import uvicorn

    from . import worker
    from .web import create_app

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings()
    i18n.set_language(settings.lang)
    db.init_db(settings.db_path)
    app = create_app(settings)
    worker.start(settings)
    uvicorn.run(app, host=settings.web_host, port=settings.web_port, log_level="warning", access_log=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secwatch", description="Attack monitor for a Linux server and Supabase.")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("run", help="start the monitor and dashboard (default; used by the service)")
    p_setup = sub.add_parser("setup", help="interactive configuration: logs, password, Telegram, Supabase")
    p_doctor = sub.add_parser("doctor", help="check logs, permissions and connections")
    for p in (p_setup, p_doctor):
        p.add_argument("--env-file", help="settings file (default: /etc/secwatch/secwatch.env or ./.env)")
    p_setup.add_argument("--host-root", default=os.getenv("SECWATCH_HOST_ROOT", "/"),
                         help="where the host filesystem is mounted (Docker: /host)")
    p_probe = sub.add_parser("probe", help="check a server from the outside: open ports, HTTPS, secret files, APIs")
    p_probe.add_argument("targets", nargs="*", help="sites to check, e.g. https://example.com (env SECWATCH_PROBE_TARGETS)")
    p_probe.add_argument("--must-deny", action="append", default=[],
                         help="URL that must refuse requests without login (repeatable; env SECWATCH_PROBE_MUST_DENY)")
    p_probe.add_argument("--allowed-ports", help="ports that may be open (default 22,80,443; env SECWATCH_PROBE_ALLOWED_PORTS)")
    p_probe.add_argument("--telegram", action="store_true",
                         help="send the report to SECWATCH_TELEGRAM_TOKEN / SECWATCH_TELEGRAM_CHAT_ID")
    p_probe.add_argument("--notify-ok", action="store_true", help="with --telegram: also report when all is fine")
    p_probe.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low", "never"],
                         help="exit with 1 if a problem of this severity or worse is found (default: high)")
    parser.add_argument("--version", action="version", version=f"secwatch {__version__}")
    args = parser.parse_args(argv)

    if args.command == "setup":
        from .setup_wizard import run_setup
        try:
            run_setup(args.env_file, root=args.host_root)
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled, nothing saved.")
            return 1
        return 0
    if args.command == "doctor":
        from .doctor import report, run_checks
        from .envfile import find_env_file, load_into_environ
        path = find_env_file(args.env_file)
        load_into_environ(path)
        if path.startswith("/etc/secwatch/"):
            # The systemd unit sets these; a shell started by hand does not.
            for key, value in SERVICE_DEFAULTS.items():
                os.environ.setdefault(key, value)
        return report(run_checks(Settings()))
    if args.command == "probe":
        return probe_command(args)
    serve()
    return 0


def probe_command(args: argparse.Namespace) -> int:
    from .probe import (DEFAULT_ALLOWED_PORTS, ProbeConfig, format_report, parse_list, run_probe,
                        send_telegram, should_fail)
    i18n.set_language(os.getenv("SECWATCH_LANG", "en"))
    targets = parse_list(args.targets) or parse_list(os.getenv("SECWATCH_PROBE_TARGETS"))
    if not targets:
        print("Nothing to check: pass sites, e.g. `secwatch probe https://example.com`.", file=sys.stderr)
        return 2
    ports = parse_list(args.allowed_ports or os.getenv("SECWATCH_PROBE_ALLOWED_PORTS")) or DEFAULT_ALLOWED_PORTS
    cfg = ProbeConfig(targets=targets,
                      must_deny=parse_list(args.must_deny) or parse_list(os.getenv("SECWATCH_PROBE_MUST_DENY")),
                      allowed_ports={int(p) for p in ports})
    findings = run_probe(cfg)
    print(format_report(findings, targets))
    if args.telegram:
        token, chat = os.getenv("SECWATCH_TELEGRAM_TOKEN", ""), os.getenv("SECWATCH_TELEGRAM_CHAT_ID", "")
        if not (token and chat):
            print("--telegram: SECWATCH_TELEGRAM_TOKEN and SECWATCH_TELEGRAM_CHAT_ID are not set.", file=sys.stderr)
            return 2
        if findings or args.notify_ok:
            error = send_telegram(token, chat, format_report(findings, targets, html=True))
            if error:
                print(f"Telegram delivery failed: {error}", file=sys.stderr)
                return 2
            print("Report sent to Telegram.")
    return 1 if should_fail(findings, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
