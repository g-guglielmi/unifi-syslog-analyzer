FROM python:3.13-slim

LABEL org.opencontainers.image.source="https://github.com/g-guglielmi/unifi-syslog-analyzer" \
      org.opencontainers.image.description="Zone-pair traffic mining and live dashboard from UniFi firewall syslog" \
      org.opencontainers.image.licenses="MIT"

# Stdlib only — no pip install layer at all.
WORKDIR /app
COPY app/ /app/
COPY test_harness.py /app/

RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin analyzer \
    && mkdir -p /data && chown analyzer:analyzer /data

USER analyzer
VOLUME /data

ENV DB_PATH=/data/flows.db \
    SYSLOG_PORT=5514 \
    HTTP_PORT=8080 \
    PYTHONUNBUFFERED=1

EXPOSE 5514/udp 8080/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD ["python3", "-c", "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('HTTP_PORT','8080')+'/api/summary',timeout=4)"]

CMD ["python3", "/app/main.py"]
