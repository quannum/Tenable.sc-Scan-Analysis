FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN useradd --create-home --shell /usr/sbin/nologin appuser

COPY requirements.txt pyproject.toml readme.md LICENSE main.py ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir ".[live]"

RUN mkdir -p /data/output && chown -R appuser:appuser /app /data

USER appuser

ENTRYPOINT ["python", "-m", "src.tenable_coverage_workflow.service_runner"]
