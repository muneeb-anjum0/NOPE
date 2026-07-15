FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOME=/tmp
ENV SEMGREP_SEND_METRICS=off
ENV TRIVY_CACHE_DIR=/tmp/trivy
WORKDIR /app

RUN addgroup --system nope && adduser --system --ingroup nope nope

ARG GITLEAKS_VERSION=8.28.0
ARG OSV_SCANNER_VERSION=2.2.3
ARG TRIVY_VERSION=0.72.0
ARG HADOLINT_VERSION=2.14.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg tar unzip \
    && rm -rf /var/lib/apt/lists/*

RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && . /etc/os-release \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian ${VERSION_CODENAME} stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks \
    && curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
      -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner \
    && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
    | tar -xz -C /usr/local/bin trivy \
    && curl -fsSL "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-linux-x86_64" \
      -o /usr/local/bin/hadolint \
    && chmod +x /usr/local/bin/hadolint \
    && mkdir -p /tmp/trivy \
    && chmod 0777 /tmp/trivy \
    && mkdir -p /app/.nope-workspaces \
    && chmod 0777 /app/.nope-workspaces

COPY apps/api/requirements.txt /app/apps/api/requirements.txt
RUN pip install --no-cache-dir -r /app/apps/api/requirements.txt

COPY apps/api /app/apps/api
COPY apps/worker /app/apps/worker
COPY security-packs /app/security-packs

ENV PYTHONPATH=/app/apps/api
USER nope

EXPOSE 8000
CMD ["uvicorn", "nope_api.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "apps/api"]
