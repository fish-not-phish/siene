# Pin registry version so the GC binary copied below matches the running container.
# Update both this and siene-registry image tag together.
FROM registry:3.1.1 AS registry-bin

FROM python:3.12-slim

# System deps + curl for binary installs
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    curl \
    skopeo \
    && rm -rf /var/lib/apt/lists/*

# ── Aikido Safe Chain ─────────────────────────────────────────────────────────
# Intercepts pip/apt installs and checks packages for malware before installation.
RUN curl -fsSL https://github.com/AikidoSec/safe-chain/releases/download/1.5.8/install-safe-chain.sh \
    | sh -s -- --ci

# ── Trivy (vulnerability scanning) ───────────────────────────────────────────
# Install the latest stable release via the official install script
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Syft (SBOM generation) ────────────────────────────────────────────────────
# Install the latest stable release via the official install script
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Cosign (container image signature verification) ───────────────────────────
# Pin to a specific release; update the version tag when you want to upgrade
RUN COSIGN_VERSION="v2.4.3" && \
    curl -sSfL \
      "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" \
      -o /usr/local/bin/cosign && \
    chmod +x /usr/local/bin/cosign

# ── Notation (OCI image signing — Notary Project) ─────────────────────────────
RUN NOTATION_VERSION="1.3.2" && \
    curl -sSfL \
      "https://github.com/notaryproject/notation/releases/download/v${NOTATION_VERSION}/notation_${NOTATION_VERSION}_linux_amd64.tar.gz" \
      -o /tmp/notation.tar.gz && \
    tar -xzf /tmp/notation.tar.gz -C /usr/local/bin notation && \
    chmod +x /usr/local/bin/notation && \
    rm /tmp/notation.tar.gz

# Copy the registry binary for garbage-collect (blob GC after tag deletion).
# Version must match the registry:3.1.1 container running alongside the worker.
COPY --from=registry-bin /bin/registry /usr/local/bin/registry

WORKDIR /app

# Install Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# certs dir is a named volume so keys persist across restarts
RUN mkdir -p /app/certs /app/staticfiles

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]
