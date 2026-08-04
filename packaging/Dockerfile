# base pinned by digest (resolved from the Docker Hub registry, 2026-08);
# dependabot/renovate should bump the digest as new 3.11-slim builds land
FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

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
