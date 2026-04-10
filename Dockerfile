FROM python:3.11-slim

LABEL org.opencontainers.image.title="vibe-guard"
LABEL org.opencontainers.image.description="AI-aware security scanner"
LABEL org.opencontainers.image.source="https://github.com/ahmbt/vibe-guard"
LABEL org.opencontainers.image.licenses="MIT"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir . \
    && pip install --no-cache-dir semgrep detect-secrets

WORKDIR /scan
ENTRYPOINT ["vibe-guard"]
CMD ["scan", ".", "--format", "terminal"]
