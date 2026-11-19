# BigQuery/Dataplex MCP Cloud Run service image.

FROM --platform=linux/amd64 python:3.11-slim-bookworm

RUN useradd --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY app/ ./app/

RUN chown -R appuser:appuser /app

USER appuser

ENV PORT=8080
ENV HOME=/app

CMD ["python", "-m", "app.main"]
