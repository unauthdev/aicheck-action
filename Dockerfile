FROM python:3.11-slim

RUN pip install --no-cache-dir httpx pyyaml

WORKDIR /opt/aicheck
COPY aicheck/ ./aicheck/

# Usage: docker run ghcr.io/unauthdev/aicheck:v1 <target> --allow-private --fail-grade F
ENTRYPOINT ["python", "-m", "aicheck.scan"]
