FROM aquasec/trivy:0.58.2@sha256:665030f4d33a82c1e8d9d5e0453365842236723c1ee5cc3becca698268e66a56 AS trivy-bin

FROM python:3.11-slim-bookworm@sha256:a36c24f9cbdf4fd0f52d67f0823eeac19c2028c637cecc392d97f980d4fec56b

ARG TRIVY_VERSION=0.58.2
ARG OSV_SCANNER_VERSION=2.3.3
ARG SYFT_VERSION=1.52.0
ARG GRYPE_VERSION=0.119.0
ARG GITLEAKS_VERSION=8.30.1
ARG SCORECARD_VERSION=5.5.0
ARG ZAP_VERSION=2.17.0
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

RUN python -c 'import hashlib, os, urllib.request; arch = os.environ["TARGETARCH"]; version = os.environ["SYFT_VERSION"]; filename = f"syft_{version}_linux_{arch}.tar.gz"; base = f"https://github.com/anchore/syft/releases/download/v{version}"; source = f"/tmp/{filename}"; urllib.request.urlretrieve(f"{base}/{filename}", source); sums = urllib.request.urlopen(f"{base}/syft_{version}_checksums.txt").read().decode(); expected = next(line.split()[0] for line in sums.splitlines() if len(line.split()) >= 2 and line.split()[-1] == filename); digest = hashlib.file_digest(open(source, "rb"), "sha256").hexdigest(); assert digest == expected, "Syft release checksum mismatch"; import tarfile; archive = tarfile.open(source); member = archive.getmember("syft"); extracted = archive.extractfile(member); target = open("/usr/local/bin/syft", "wb"); target.write(extracted.read()); target.close(); os.chmod("/usr/local/bin/syft", 0o755)'

RUN python -c 'import hashlib, os, urllib.request, tarfile; arch = os.environ["TARGETARCH"]; version = os.environ["GRYPE_VERSION"]; filename = f"grype_{version}_linux_{arch}.tar.gz"; base = f"https://github.com/anchore/grype/releases/download/v{version}"; source = f"/tmp/{filename}"; urllib.request.urlretrieve(f"{base}/{filename}", source); sums = urllib.request.urlopen(f"{base}/grype_{version}_checksums.txt").read().decode(); expected = next(line.split()[0] for line in sums.splitlines() if len(line.split()) >= 2 and line.split()[-1] == filename); digest = hashlib.file_digest(open(source, "rb"), "sha256").hexdigest(); assert digest == expected, "Grype release checksum mismatch"; archive = tarfile.open(source); member = archive.getmember("grype"); extracted = archive.extractfile(member); target = open("/usr/local/bin/grype", "wb"); target.write(extracted.read()); target.close(); os.chmod("/usr/local/bin/grype", 0o755)'

RUN python -c 'import hashlib, os, urllib.request, tarfile; version = os.environ["GITLEAKS_VERSION"]; asset_arch = {"amd64": "x64", "arm64": "arm64"}[os.environ["TARGETARCH"]]; filename = f"gitleaks_{version}_linux_{asset_arch}.tar.gz"; base = f"https://github.com/gitleaks/gitleaks/releases/download/v{version}"; source = f"/tmp/{filename}"; urllib.request.urlretrieve(f"{base}/{filename}", source); sums = urllib.request.urlopen(f"{base}/gitleaks_{version}_checksums.txt").read().decode(); expected = next(line.split()[0] for line in sums.splitlines() if len(line.split()) >= 2 and line.split()[-1] == filename); digest = hashlib.file_digest(open(source, "rb"), "sha256").hexdigest(); assert digest == expected, "Gitleaks release checksum mismatch"; archive = tarfile.open(source); member = archive.getmember("gitleaks"); extracted = archive.extractfile(member); target = open("/usr/local/bin/gitleaks", "wb"); target.write(extracted.read()); target.close(); os.chmod("/usr/local/bin/gitleaks", 0o755)'

RUN python -c 'import hashlib, os, urllib.request, tarfile; arch = os.environ["TARGETARCH"]; version = os.environ["SCORECARD_VERSION"]; filename = f"scorecard_{version}_linux_{arch}.tar.gz"; base = f"https://github.com/ossf/scorecard/releases/download/v{version}"; source = f"/tmp/{filename}"; urllib.request.urlretrieve(f"{base}/{filename}", source); sums = urllib.request.urlopen(f"{base}/scorecard_checksums.txt").read().decode(); expected = next(line.split()[0] for line in sums.splitlines() if len(line.split()) >= 2 and line.split()[-1] == filename); digest = hashlib.file_digest(open(source, "rb"), "sha256").hexdigest(); assert digest == expected, "Scorecard release checksum mismatch"; archive = tarfile.open(source); member = archive.getmember("scorecard"); extracted = archive.extractfile(member); target = open("/usr/local/bin/scorecard", "wb"); target.write(extracted.read()); target.close(); os.chmod("/usr/local/bin/scorecard", 0o755)'

RUN apt-get update \
    && apt-get install --no-install-recommends --yes git openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

RUN python -c 'import hashlib, urllib.request; source="/tmp/ZAP_2.17.0_Linux.tar.gz"; urllib.request.urlretrieve("https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz", source); digest=hashlib.file_digest(open(source, "rb"), "sha256").hexdigest(); assert digest == "efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a", "ZAP release checksum mismatch"'
RUN mkdir -p /opt/zap \
    && tar -xzf /tmp/ZAP_2.17.0_Linux.tar.gz --strip-components=1 -C /opt/zap \
    && rm /tmp/ZAP_2.17.0_Linux.tar.gz

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
