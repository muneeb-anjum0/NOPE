FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOME=/tmp
ENV SEMGREP_SEND_METRICS=off
WORKDIR /app

RUN addgroup --system nope && adduser --system --ingroup nope nope

COPY apps/api/requirements.txt /app/apps/api/requirements.txt
RUN pip install --no-cache-dir -r /app/apps/api/requirements.txt

COPY apps/api /app/apps/api
COPY apps/worker /app/apps/worker
COPY security-packs /app/security-packs

ENV PYTHONPATH=/app/apps/api
USER nope

EXPOSE 8000
CMD ["uvicorn", "nope_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "apps/api"]
