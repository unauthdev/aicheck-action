FROM python:3.11-slim

WORKDIR /opt/aicheck
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
COPY docs/PROBES.md ./docs/PROBES.md
# TODO(PR packaging): once aicheck-scan is on PyPI, replace the local-source
# install with `pip install --no-cache-dir aicheck-scan==${VERSION}`.
RUN pip install --no-cache-dir .

# Default: single-host CI scan. For estate inventory:
#   docker run --rm --network host \
#     -v "$PWD/targets.yaml:/targets.yaml:ro" \
#     -v "$PWD/state:/state" \
#     ghcr.io/unauthdev/aicheck:v1 \
#     inventory --targets /targets.yaml --state-dir /state --allow-private
ENTRYPOINT ["aicheck"]
