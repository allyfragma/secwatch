from __future__ import annotations

import secrets
from datetime import date, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

from .config import Settings
from .geo import Geo
from .i18n import get_language, t
from .summary import build_summary

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
TEMPLATES.env.globals.update(t=t, lang=get_language)


def create_app(settings: Settings) -> FastAPI:
    if not settings.web_password and not settings.allow_no_auth:
        raise RuntimeError("SECWATCH_WEB_PASSWORD is required (or SECWATCH_ALLOW_NO_AUTH=1 for local tests only)")
    app = FastAPI(title="secwatch", docs_url=None, redoc_url=None, openapi_url=None)
    basic = HTTPBasic(auto_error=False)
    geo = Geo.for_settings(settings)

    def auth(creds: HTTPBasicCredentials | None = Depends(basic)) -> None:
        if settings.allow_no_auth and not settings.web_password:
            return
        ok = creds is not None and secrets.compare_digest(creds.username.encode(), settings.web_user.encode()) \
            and secrets.compare_digest(creds.password.encode(), settings.web_password.encode())
        if not ok:
            raise HTTPException(status_code=401, headers={"WWW-Authenticate": 'Basic realm="secwatch"'})

    def parse_day(day: str | None) -> date:
        if not day:
            return datetime.now(ZoneInfo(settings.timezone)).date()
        try:
            return date.fromisoformat(day)
        except ValueError:
            raise HTTPException(status_code=400, detail="day must be YYYY-MM-DD")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/api/summary", dependencies=[Depends(auth)])
    def api_summary(day: str | None = Query(None)):
        return JSONResponse(build_summary(settings, parse_day(day), geo))

    @app.post("/api/analyze", dependencies=[Depends(auth)])
    def api_analyze():
        raise HTTPException(status_code=501, detail=t("web.analyze_later"))

    @app.get("/", response_class=HTMLResponse, dependencies=[Depends(auth)])
    def index(request: Request, day: str | None = Query(None)):
        d = parse_day(day)
        s = build_summary(settings, d, geo)
        max_hour = max(s["hours"]) or 1
        max_trend = max(t["count"] for t in s["trend"]) or 1
        return TEMPLATES.TemplateResponse(request, "index.html", {
            "s": s, "max_hour": max_hour, "max_trend": max_trend,
            "prev_day": date.fromordinal(d.toordinal() - 1).isoformat(),
            "next_day": date.fromordinal(d.toordinal() + 1).isoformat(),
        })

    return app
