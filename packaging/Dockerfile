FROM python:3.11-slim

WORKDIR /opt/aicheck
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
# TODO(PR packaging): once aicheck-scan is on PyPI, replace the local-source
# install with `pip install --no-cache-dir aicheck-scan==${VERSION}`.
RUN pip install --no-cache-dir .

# Usage: docker run ghcr.io/unauthdev/aicheck:v1 <target> --allow-private --fail-grade F
ENTRYPOINT ["aicheck"]
