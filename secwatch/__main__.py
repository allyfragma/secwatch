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
    serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
