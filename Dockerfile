# SPDX-License-Identifier: AGPL-3.0-only
FROM python:3.12-slim

LABEL org.opencontainers.image.title="wazuh-daily-triage" \
      org.opencontainers.image.description="AI-assisted daily triage for Wazuh SIEM" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/dururustem68/wazuh-daily-triage"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    WDT_CONFIG=/app/config/environments.yaml \
    FORWARDED_ALLOW_IPS=127.0.0.1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt && \
    useradd --system --uid 10001 --home /app triage

COPY LICENSE NOTICE ./
COPY app ./app
COPY config/demo.yaml config/environments.example.yaml ./config/
COPY config/context/demo.md config/context/example.md ./config/context/
COPY config/seed/example.yaml ./config/seed/

USER 10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"

# Behind a reverse proxy set FORWARDED_ALLOW_IPS to the proxy's address only ("*" allows X-Forwarded-For spoofing).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
