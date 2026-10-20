# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY secwatch ./secwatch
COPY tools ./tools

# Test image: docker build --target test -t secwatch:test . && docker run --rm secwatch:test
FROM base AS test
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY tests ./tests
CMD ["python", "-m", "pytest", "-q"]

# Runtime image (default target).
FROM base AS runtime
ARG VERSION=dev
LABEL org.opencontainers.image.title="secwatch"       org.opencontainers.image.description="See who attacks your server and what to fix"       org.opencontainers.image.source="https://github.com/allyfragma/secwatch"       org.opencontainers.image.licenses="MIT"       org.opencontainers.image.version="${VERSION}"
# Group 4 = adm on Debian/Ubuntu hosts: lets the container read /var/log/auth.log, nginx and fail2ban logs.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin --groups adm secwatch \
    && mkdir -p /data && chown secwatch /data
USER secwatch
EXPOSE 8088
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8088/healthz', timeout=3)"
# `docker run IMAGE setup|doctor` runs the CLI; no argument starts the monitor.
ENTRYPOINT ["python", "-m", "secwatch"]
CMD ["run"]
