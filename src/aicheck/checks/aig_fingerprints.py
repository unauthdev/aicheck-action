"""Additive fingerprint rules from vendored AI-Infra-Guard GET-only YAMLs.

Loads `vendor/ai-infra-guard/fingerprints/*.yaml` and emits Finding objects in
the standard shape when matchers hit. Products that already have a primary
checker only emit here when that primary returns nothing — additive coverage
without duplicating findings on the same fixture/scan.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from ..models import Finding, ProbeResult

# Not named CHECK_ID — this module emits per-fingerprint ids
# (`aig-fingerprint:<stem>`) and must not register as a playground block.
RULE_ID_PREFIX = "aig-fingerprint"
VENDOR_FP_DIR = Path(__file__).resolve().parents[2] / "vendor" / "ai-infra-guard" / "fingerprints"

# Default ports we probe (recon) / accept in fixtures for each fingerprint stem.
PORT_CANDIDATES: dict[str, list[int]] = {
    "ollama": [11434],
    "vllm": [8000],
    "n8n.io": [5678],
    "jupyter-notebook": [8888],
    "jupyter-lab": [8888],
    "jupyter-server": [8888],
    "mlflow": [5000, 5001],
    "litellm": [4000],
    "ray": [8265],
    "kubeflow": [8080],
    "dify": [80, 3000, 5001],
    "flowise": [3000],
    "openwebui": [8080],
    "mcp": [3000, 3001, 5000, 8000, 8080],
    "gradio": [7860],
    "lm-studio": [1234],
    "qdrant": [6333],
    "chroma": [8000],
    "weaviate": [8080],
}

# Primary checker module names that already cover a fingerprint stem.
PRIMARY_CHECKERS: dict[str, str] = {
    "ollama": "ollama",
    "vllm": "vllm",
    "n8n.io": "n8n",
    "jupyter-notebook": "jupyter",
    "jupyter-lab": "jupyter",
    "jupyter-server": "jupyter",
    "ray": "ray",
    "dify": "dify",
    "flowise": "flowise",
    "openwebui": "openwebui",
    "mcp": "mcp",
    "gradio": "gradio_langflow",
    "qdrant": "qdrant",
    "chroma": "chroma",
    "weaviate": "weaviate",
}

PRODUCT_LABEL: dict[str, str] = {
    "ollama": "Ollama",
    "vllm": "vLLM",
    "n8n.io": "n8n",
    "jupyter-notebook": "Jupyter",
    "jupyter-lab": "Jupyter",
    "jupyter-server": "Jupyter",
    "mlflow": "MLflow",
    "litellm": "LiteLLM",
    "ray": "Ray",
    "kubeflow": "Kubeflow",
    "dify": "Dify",
    "flowise": "Flowise",
    "openwebui": "Open WebUI",
    "mcp": "MCP",
    "gradio": "Gradio",
    "lm-studio": "LM Studio",
    "qdrant": "Qdrant",
    "chroma": "Chroma",
    "weaviate": "Weaviate",
}

FIX_CARD: dict[str, str] = {
    "ollama": "ollama-exposed",
    "vllm": "vllm-exposed",
    "n8n.io": "n8n-exposed",
    "jupyter-notebook": "jupyter-exposed",
    "jupyter-lab": "jupyter-exposed",
    "jupyter-server": "jupyter-exposed",
    "mlflow": "mlflow-exposed",
    "litellm": "litellm-exposed",
    "ray": "ray-exposed",
    "kubeflow": "kubeflow-exposed",
    "dify": "dify-exposed",
    "flowise": "flowise-exposed",
    "openwebui": "open-webui-exposed",
    "mcp": "mcp-exposed",
    "gradio": "gradio-exposed",
    "lm-studio": "lmstudio-exposed",
    "qdrant": "qdrant-exposed",
    "chroma": "chroma-exposed",
    "weaviate": "weaviate-exposed",
}

_TERM_RE = re.compile(
    r'(body|header|icon)\s*=\s*"((?:\\.|[^"\\])*)"'
)


def _eval_atom(kind: str, needle: str, body: str, headers: str) -> bool:
    if kind == "body":
        return needle in body
    if kind == "header":
        return needle.lower() in headers.lower()
    if kind == "icon":
        return False  # favicon hash not gathered; ignore icon-only branches
    return False


def eval_matcher_expr(expr: str, body: str, headers: str = "") -> bool:
    """Evaluate AIG matcher expressions: body/header/icon atoms with && / ||."""
    expr = expr.strip()
    if "||" in expr:
        return any(eval_matcher_expr(p, body, headers) for p in expr.split("||"))
    if "&&" in expr:
        return all(eval_matcher_expr(p, body, headers) for p in expr.split("&&"))
    m = _TERM_RE.fullmatch(expr.strip())
    if not m:
        return False
    return _eval_atom(m.group(1), m.group(2).encode().decode("unicode_escape"), body, headers)


def load_fingerprints(directory: Path | None = None) -> list[dict]:
    directory = directory or VENDOR_FP_DIR
    out: list[dict] = []
    if not directory.is_dir():
        return out
    for path in sorted(directory.glob("*.yaml")):
        # Strip attribution comment lines for YAML parse
        raw = path.read_text()
        lines = [ln for ln in raw.splitlines() if not ln.startswith("#")]
        doc = yaml.safe_load("\n".join(lines)) or {}
        stem = path.stem
        out.append({"stem": stem, "path": path, "doc": doc})
    return out


def fingerprint_matches(doc: dict, facts: dict[str, ProbeResult], ports: list[int]) -> tuple[bool, ProbeResult | None, str]:
    """Return (matched, probe, evidence) for the http matcher blocks."""
    blocks = doc.get("http") or []
    if isinstance(blocks, dict):
        blocks = [blocks]
    for block in blocks:
        if not isinstance(block, dict):
            continue
        if str(block.get("method", "GET")).upper() != "GET":
            continue
        path = block.get("path") or "/"
        if isinstance(path, list):
            path = path[0]
        path = str(path)
        if not path.startswith("/"):
            path = "/" + path
        matchers = block.get("matchers") or []
        for port in ports:
            key = f"{port}:{path}"
            probe = facts.get(key)
            if probe is None or not probe.ok:
                continue
            headers = ""
            body = probe.body or ""
            if not matchers:
                return True, probe, f"GET {probe.url} → 200"
            for m in matchers:
                expr = m if isinstance(m, str) else str(m)
                if eval_matcher_expr(expr, body, headers):
                    return True, probe, f"GET {probe.url} → 200 matched {expr!r}"
    return False, None, ""


def _url_for(probe: ProbeResult) -> str:
    try:
        after_scheme = probe.url.split("://", 1)[1]
        hostport, _, path = after_scheme.partition("/")
        port = hostport.rsplit(":", 1)[-1]
        return f"http://TARGET:{port}/{path}"
    except Exception:
        return probe.url


def extract_version(doc: dict, facts: dict[str, ProbeResult], ports: list[int]) -> str:
    """Run vendored version extractors against probe bodies. Header-only
    extractors are skipped — recon stores bodies, not response headers.
    Returns "" when nothing was actually extracted."""
    blocks = doc.get("version") or []
    if isinstance(blocks, dict):
        blocks = [blocks]
    for block in blocks:
        if not isinstance(block, dict):
            continue
        if str(block.get("method", "GET")).upper() != "GET":
            continue
        path = block.get("path") or "/"
        if isinstance(path, list):
            path = path[0]
        path = str(path)
        if not path.startswith("/"):
            path = "/" + path
        extractor = block.get("extractor") or {}
        if str(extractor.get("part", "body")).lower() != "body":
            continue
        pattern = extractor.get("regex") or ""
        if not pattern:
            continue
        group = int(extractor.get("group") or 1)
        try:
            cre = re.compile(pattern)
        except re.error:
            continue
        for port in ports:
            probe = facts.get(f"{port}:{path}")
            if probe is None or not probe.ok:
                continue
            m = cre.search(probe.body or "")
            if not m:
                continue
            try:
                ver = m.group(group)
            except IndexError:
                continue
            if ver:
                return str(ver)
    return ""


def finding_for_fingerprint(
    stem: str, doc: dict, probe: ProbeResult, evidence: str, version: str = ""
) -> Finding:
    product = PRODUCT_LABEL.get(stem, stem)
    info = doc.get("info") or {}
    if version:
        evidence = f"{evidence}; version {version}"
    details = {
        "source": "ai-infra-guard-fingerprint",
        "fingerprint": stem,
        "severity_upstream": info.get("severity", "info"),
    }
    if version:
        details["version"] = version
    return Finding(
        check_id=f"{RULE_ID_PREFIX}:{stem}",
        product=product,
        title=f"{product} fingerprinted via unauthenticated GET",
        severity="MEDIUM",
        url=_url_for(probe),
        evidence=evidence,
        fix_card_id=FIX_CARD.get(stem, "mlflow-exposed"),
        details=details,
    )


def evaluate_all(facts: dict[str, ProbeResult], directory: Path | None = None) -> list[Finding]:
    """Evaluate every vendored fingerprint (no primary-skip). Used by fixtures."""
    findings: list[Finding] = []
    for item in load_fingerprints(directory):
        stem = item["stem"]
        ports = PORT_CANDIDATES.get(stem, [])
        ok, probe, evidence = fingerprint_matches(item["doc"], facts, ports)
        if ok and probe is not None:
            ver = extract_version(item["doc"], facts, ports)
            findings.append(
                finding_for_fingerprint(stem, item["doc"], probe, evidence, ver)
            )
    return findings


def detect(facts: dict[str, ProbeResult]) -> list[Finding]:
    """Additive rules: emit only when no primary checker already found the product."""
    from . import (
        chroma,
        dify,
        flowise,
        gradio_langflow,
        jupyter,
        mcp,
        n8n,
        ollama,
        openwebui,
        qdrant,
        ray,
        vllm,
        weaviate,
    )

    primaries = {
        "ollama": ollama,
        "vllm": vllm,
        "n8n": n8n,
        "jupyter": jupyter,
        "ray": ray,
        "dify": dify,
        "flowise": flowise,
        "openwebui": openwebui,
        "mcp": mcp,
        "gradio_langflow": gradio_langflow,
        "qdrant": qdrant,
        "chroma": chroma,
        "weaviate": weaviate,
    }

    primary_hit: set[str] = set()
    for name, mod in primaries.items():
        try:
            if mod.detect(facts):
                primary_hit.add(name)
        except Exception:
            continue

    findings: list[Finding] = []
    for item in load_fingerprints():
        stem = item["stem"]
        primary = PRIMARY_CHECKERS.get(stem)
        if primary and primary in primary_hit:
            continue
        ports = PORT_CANDIDATES.get(stem, [])
        ok, probe, evidence = fingerprint_matches(item["doc"], facts, ports)
        if ok and probe is not None:
            ver = extract_version(item["doc"], facts, ports)
            findings.append(
                finding_for_fingerprint(stem, item["doc"], probe, evidence, ver)
            )
    return findings


def coverage_entries() -> list[dict]:
    """Product-documentation rows for /rules — one per vendored fingerprint."""
    by_product: dict[str, list[dict]] = {}
    for item in load_fingerprints():
        stem = item["stem"]
        product = PRODUCT_LABEL.get(stem, stem)
        primary = PRIMARY_CHECKERS.get(stem)
        note = (
            "Additive GET fingerprint. Skipped when the primary checker already fired."
            if primary
            else "GET fingerprint — the scanner's detection for this service."
        )
        by_product.setdefault(product, []).append(
            {
                "stem": stem,
                "id": f"fp-{stem.replace('.', '-')}",
                "severity": "medium",
                "text": f"{product} fingerprinted via unauthenticated GET",
                "note": note,
            }
        )
    # Stable order matching PRODUCT_LABEL declaration.
    order = list(dict.fromkeys(PRODUCT_LABEL.values()))
    return [
        {"product": product, "detections": by_product[product]}
        for product in order
        if product in by_product
    ]
