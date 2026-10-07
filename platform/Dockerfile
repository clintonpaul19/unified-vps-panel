FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV UVPS_WEB_DIR=/app/web

WORKDIR /app

COPY platform/api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY platform/api/app /app/app
COPY platform/web /app/web

RUN useradd --system --create-home --uid 10001 uvps && chown -R uvps:uvps /app
USER uvps

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/readyz", timeout=3)'

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--proxy-headers", "--timeout-graceful-shutdown", "20"]
