"""Version→CVE annotation against vendored vuln_lookup.json.

When a finding already carries an extracted version in details["version"],
append a display-only line (details["known_cves"]) naming the count and worst
CVE id from the snapshot lookup. Never invents a version. Never changes
severity — grading is untouched.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from .cvemap import _in_range, _parse_version
from ..models import Finding

LOOKUP_PATH = (
    Path(__file__).resolve().parents[2]
    / "vendor"
    / "ai-infra-guard"
    / "vuln_lookup.json"
)

_ATOM_RE = re.compile(
    r'^version\s*(>=|<=|==|>|<|=|!=)\s*"([^"]*)"\s*$'
)

# Finding.product → vuln_lookup.json product keys (case-insensitive match).
_PRODUCT_KEYS: dict[str, tuple[str, ...]] = {
    "Ollama": ("ollama",),
    "vLLM": ("vllm", "vLLM"),
    "n8n": ("n8n",),
    "Jupyter": ("jupyter-notebook", "jupyter-server", "jupyterlab", "jupyter"),
    "MLflow": ("mlflow", "MLflow"),
    "LiteLLM": ("litellm", "LiteLLM"),
    "Ray": ("ray",),
    "Kubeflow": ("kubeflow",),
    "Dify": ("dify", "Dify"),
    "Flowise": ("flowise", "Flowise"),
    "Open WebUI": ("open-webui", "openwebui", "Open WebUI"),
    "MCP": ("mcp", "mcp sse"),
    "Gradio": ("gradio", "Gradio"),
    "LM Studio": ("lmstudio", "llmstudio", "lm-studio"),
    "Langfuse": ("langfuse",),
    "ComfyUI": ("comfyui",),
    "Langflow": ("langflow",),
    "Qdrant": ("qdrant",),
    "Chroma": ("chroma",),
    "Weaviate": ("weaviate",),
    "AnythingLLM": ("anythingllm",),
}

_SEV_RANK = {
    "critical": 4, "严重": 4, "危急": 4,
    "high": 3, "高": 3, "高危": 3,
    "medium": 2, "中等": 2, "中危": 2,
    "low": 1, "低": 1,
    "unknown": 0,
}


@lru_cache(maxsize=1)
def _entries() -> list[dict]:
    if not LOOKUP_PATH.is_file():
        return []
    data = json.loads(LOOKUP_PATH.read_text(encoding="utf-8"))
    return list(data.get("entries") or [])


def _split_top(expr: str, sep: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    buf: list[str] = []
    i = 0
    while i < len(expr):
        ch = expr[i]
        if ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth -= 1
            buf.append(ch)
        elif depth == 0 and expr.startswith(sep, i):
            parts.append("".join(buf))
            buf = []
            i += len(sep) - 1
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def _outer_parens_wrap(expr: str) -> bool:
    """True when the opening '(' is closed by the final char, i.e. the
    parens wrap the entire expression: '(a && b)' yes, '(a) && (b)' no."""
    depth = 0
    for i, ch in enumerate(expr):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i == len(expr) - 1
    return False


def _eval_atom(atom: str, version: tuple[int, ...]) -> bool | None:
    """True/False if parseable; None if the atom is not a version compare."""
    m = _ATOM_RE.match(atom.strip())
    if not m:
        return None
    op, raw = m.groups()
    if op == "!=":
        bound = _parse_version(raw)
        if bound is None:
            return None
        from .cvemap import _cmp
        return _cmp(version, bound) != 0
    if op == "=":
        op = "=="
    if not raw:
        return False
    return _in_range(version, f"{op} {raw}")


def rule_matches(rule: str, version_str: str) -> bool:
    """Evaluate a vuln_lookup rule against an extracted version string."""
    version = _parse_version(version_str)
    if version is None:
        return False
    rule = (rule or "").strip()
    if not rule or "version" not in rule:
        return False

    def ev(expr: str) -> bool | None:
        expr = expr.strip()
        if not expr:
            return False
        # Strip parens wrapping the whole expression BEFORE testing for
        # operators: in '(a && b)' the '&&' is at paren depth 1, so
        # _split_top would return the expr unchanged and ev() would
        # recurse on the identical string forever.
        while expr.startswith("(") and _outer_parens_wrap(expr):
            expr = expr[1:-1].strip()
            if not expr:
                return False
        if "||" in expr:
            vals = [ev(p) for p in _split_top(expr, "||")]
            if any(v is True for v in vals):
                return True
            if all(v is False for v in vals):
                return False
            return None
        if "&&" in expr:
            vals = [ev(p) for p in _split_top(expr, "&&")]
            if any(v is False for v in vals):
                return False
            if any(v is None for v in vals):
                return None
            return True
        return _eval_atom(expr, version)

    return ev(rule) is True


def _sev_rank(raw: object) -> int:
    if raw is None:
        return 0
    return _SEV_RANK.get(str(raw).strip().lower(), 0)


def _cve_sort_key(cve: str) -> tuple[int, int]:
    m = re.match(r"CVE-(\d+)-(\d+)$", cve.upper())
    if not m:
        return (0, 0)
    return (int(m.group(1)), int(m.group(2)))


def match(product: str, version_str: str) -> list[dict]:
    """Entries from the snapshot whose rule covers the extracted version."""
    if not version_str or not str(version_str).strip():
        return []
    keys = {k.lower() for k in _PRODUCT_KEYS.get(product, (product,))}
    keys.add(product.lower())
    hits = []
    for entry in _entries():
        if str(entry.get("product", "")).lower() not in keys:
            continue
        if rule_matches(str(entry.get("rule") or ""), version_str):
            hits.append(entry)
    return hits


def format_line(hits: list[dict]) -> str:
    """e.g. '3 known CVEs · worst: CVE-2025-32434'."""
    n = len(hits)
    if n == 0:
        return ""
    worst = max(
        hits,
        key=lambda e: (_sev_rank(e.get("severity")), _cve_sort_key(str(e.get("cve") or ""))),
    )
    cve = str(worst.get("cve") or "").upper()
    label = "known CVE" if n == 1 else "known CVEs"
    return f"{n} {label} · worst: {cve}"


def annotate_known_cves(findings: list[Finding]) -> None:
    """Mutate findings in place: set details['known_cves'] when applicable.

    Only findings with a non-empty details['version']. No version → no line.
    Does not change severity, title, or check_id.
    """
    for f in findings:
        ver = (f.details or {}).get("version")
        if not ver or not str(ver).strip():
            continue
        hits = match(f.product, str(ver))
        line = format_line(hits)
        if not line:
            continue
        if f.details is None:
            f.details = {}
        f.details["known_cves"] = line
        f.details["known_cve_count"] = len(hits)
        f.details["known_cve_worst"] = line.rsplit("worst: ", 1)[-1]
