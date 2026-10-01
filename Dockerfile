FROM aquasec/trivy:0.58.2@sha256:665030f4d33a82c1e8d9d5e0453365842236723c1ee5cc3becca698268e66a56 AS trivy-bin

FROM python:3.11-slim-bookworm

ARG TRIVY_VERSION=0.58.2
ARG OSV_SCANNER_VERSION=2.3.3
ARG TARGETARCH=amd64

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src \
    HOME=/tmp \
    XDG_CACHE_HOME=/tmp/cache \
    TRIVY_CACHE_DIR=/tmp/trivy \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/* \
     && case "$TARGETARCH" in \
            amd64) osv_arch=amd64 ;; \
            arm64) osv_arch=arm64 ;; \
            *) echo "Unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
         esac \
    && curl -fsSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${osv_arch}" \
       -o /usr/local/bin/osv-scanner \
    && chmod 0755 /usr/local/bin/osv-scanner

COPY --from=trivy-bin /usr/local/bin/trivy /usr/local/bin/trivy

RUN pip install --no-cache-dir semgrep==1.99.0 PyYAML==6.0.2 \
    && useradd --uid 1000 --user-group --home-dir /nonexistent --shell /usr/sbin/nologin runner

WORKDIR /app
COPY src/ /app/src/
COPY config/default.yaml /config/default.yaml
COPY entrypoint.sh /usr/local/bin/vesper-runner-entrypoint
RUN chmod 0755 /usr/local/bin/vesper-runner-entrypoint \
    && mkdir -p /output \
    && chown -R 1000:1000 /app /config /output

USER 1000:1000
ENTRYPOINT ["/usr/local/bin/vesper-runner-entrypoint"]