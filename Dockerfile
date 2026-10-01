FROM aquasec/trivy:0.58.2@sha256:665030f4d33a82c1e8d9d5e0453365842236723c1ee5cc3becca698268e66a56 AS trivy-bin

FROM python:3.11-slim-bookworm@sha256:a36c24f9cbdf4fd0f52d67f0823eeac19c2028c637cecc392d97f980d4fec56b

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

RUN python -c 'import hashlib, os, urllib.request; arch = os.environ["TARGETARCH"]; version = os.environ["OSV_SCANNER_VERSION"]; filename = f"osv-scanner_linux_{arch}"; base = f"https://github.com/google/osv-scanner/releases/download/v{version}"; source = f"/tmp/{filename}"; urllib.request.urlretrieve(f"{base}/{filename}", source); sums = urllib.request.urlopen(f"{base}/osv-scanner_SHA256SUMS").read().decode(); expected = next(line.split()[0] for line in sums.splitlines() if len(line.split()) == 2 and line.split()[1] == filename); digest = hashlib.file_digest(open(source, "rb"), "sha256").hexdigest(); assert digest == expected, "OSV scanner release checksum mismatch"; os.replace(source, "/usr/local/bin/osv-scanner"); os.chmod("/usr/local/bin/osv-scanner", 0o755)'

COPY --from=trivy-bin /usr/local/bin/trivy /usr/local/bin/trivy

COPY requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --require-hashes --requirement /tmp/requirements.lock \
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