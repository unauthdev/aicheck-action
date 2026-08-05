"""Workflow-template security scanner — static analysis of FILES, zero probing.

Analyzes AI workflow templates (n8n, Dify, Flowise) for embedded credentials,
exfil-shaped flows, and dangerous nodes. Deterministic rules only — no LLM,
and no network traffic beyond optionally fetching the template file itself
from an https URL. The same engine feeds marketplaces, CI jobs, and end
users: anything that can hand us template text gets the same verdict.

  python -m aicheck.workflow_templates workflow.json
  aicheck template https://example.com/exported-workflow.json --format json
  aicheck template a.json b.yaml c.json        # N sources, per-file report

Detection is by shape, never by file extension:
  n8n     JSON: nodes[] + connections
  Dify    YAML DSL: app + workflow.graph.nodes[]
  Flowise JSON: flowData (a JSON string or object) with nodes[]

Exit codes (same discipline as scan.py): 0 = no CRITICAL/HIGH finding,
1 = CRITICAL or HIGH present, 2 = fetch/parse/usage error — an unreadable
template is never reported as a clean one.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlsplit

import httpx
import yaml

from .models import Finding

MAX_INPUT_BYTES = 1_000_000  # 1 MB — templates are small; bigger input is a mistake or an attack
FETCH_TIMEOUT = 10.0
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}

# Seed allowlist of well-known SaaS hosts that templates legitimately call.
# Deliberately small — flag-expandable as false positives are reviewed.
KNOWN_SAAS_HOSTS = (
    "openai.com",
    "anthropic.com",
    "googleapis.com",
    "slack.com",
    "discord.com",
)

# First-party n8n node packages. Anything else in an n8n template is a
# community package: third-party code, unpinned, unaudited by n8n.
_N8N_FIRST_PARTY_PREFIXES = (
    "n8n-nodes-base.",
    "@n8n/n8n-nodes-langchain.",
    "n8n-nodes-langchain.",
)

# Node-type suffixes (after the last ".") that execute arbitrary commands or
# code on the host running the workflow.
_DANGEROUS_SUFFIXES = {"executecommand", "ssh", "shell", "code"}

# Node-type suffixes that read data out of a store or file — one half of the
# exfil shape.
_DATA_READ_SUFFIXES = {
    "googlesheets", "googledocs", "postgres", "mysql", "mariadb",
    "readwritefile", "readbinaryfiles", "readfile", "knowledge-retrieval",
}

# Parameter keys whose string values are secrets by name (password:, apiKey:,
# ...) even when they don't match a known token shape.
_SENSITIVE_KEYS = {
    "password", "passwd", "passphrase", "api_key", "apikey", "api-key",
    "secret", "secret_key", "client_secret", "access_token", "refresh_token",
    "auth_token", "private_key", "bearer",
}

# Query-string keys that carry tokens in URLs (?token=..., ?key=...).
_URL_TOKEN_PARAMS = {
    "token", "api_key", "apikey", "key", "access_token", "auth",
    "auth_token", "secret", "password", "sig", "signature",
}

# Shaped-token literals. Order matters: the first pattern matching a span
# wins, so the more specific shapes come before generic ones.
_SECRET_PATTERNS = (
    ("Anthropic API key (sk-ant-…)", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI-style API key (sk-…)", re.compile(r"sk-[A-Za-z0-9_-]{20,}")),
    ("GitHub token (ghp_/gho_/github_pat_…)",
     re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}")),
    ("Slack token (xox…)", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("AWS access key id (AKIA…)", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key (AIza…)", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("private key block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
)

_URL_RE = re.compile(r"https?://[^\s\"'<>)\\]+")

_SHAPE_HINTS = (
    "n8n (JSON with nodes[] + connections)",
    "Dify (YAML/JSON DSL with app + workflow.graph.nodes[])",
    "Flowise (JSON with flowData containing nodes[])",
)


class TemplateParseError(Exception):
    """Input is not parseable, exceeds the size cap, or matches no known
    template shape."""


class TemplateFetchError(Exception):
    """URL source could not be fetched under the fetch contract (https-only,
    no cross-host redirects, 1 MB cap, 10 s timeout)."""


@dataclass
class TplNode:
    """One workflow node, normalized across ecosystems."""
    node_id: str
    name: str
    type: str            # ecosystem-specific type string ("" when absent)
    parameters: dict = field(default_factory=dict)
    credentials: dict = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"node {self.name!r} (id={self.node_id})"

    @property
    def type_suffix(self) -> str:
        return self.type.lower().rsplit(".", 1)[-1].rsplit("/", 1)[-1]


@dataclass
class ParsedTemplate:
    ecosystem: str       # "n8n" | "dify" | "flowise"
    name: str
    nodes: list[TplNode]
    source: str = ""     # path or URL the template came from (Finding.url)


# ---------------------------------------------------------------- parsing

def parse_template(text: str, source: str = "") -> ParsedTemplate:
    """Detect the ecosystem by shape and normalize the nodes. Raises
    TemplateParseError with a message listing what was tried when nothing
    matches."""
    if len(text.encode("utf-8", "replace")) > MAX_INPUT_BYTES:
        raise TemplateParseError(
            f"input exceeds the {MAX_INPUT_BYTES}-byte cap — refusing to parse")
    try:
        data = json.loads(text)
    except ValueError as json_err:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as yaml_err:
            raise TemplateParseError(
                f"not parseable as JSON ({json_err}) or YAML ({yaml_err})")
    if isinstance(data, dict):
        if isinstance(data.get("nodes"), list) and "connections" in data:
            return _parse_n8n(data, source)
        if "flowData" in data:
            return _parse_flowise(data, source)
        graph = (data.get("workflow") or {})
        if "app" in data and isinstance(graph, dict) and \
                isinstance((graph.get("graph") or {}).get("nodes"), list):
            return _parse_dify(data, source)
    tried = "; ".join(_SHAPE_HINTS)
    raise TemplateParseError(
        f"input parses but matches no known workflow-template shape — "
        f"tried: {tried}")


def _str(v) -> str:
    return str(v) if v is not None else ""


def _parse_n8n(data: dict, source: str) -> ParsedTemplate:
    nodes = []
    for n in data["nodes"]:
        if not isinstance(n, dict):
            continue
        nodes.append(TplNode(
            node_id=_str(n.get("id") or n.get("name") or "?"),
            name=_str(n.get("name") or n.get("id") or "?"),
            type=_str(n.get("type")),
            parameters=n.get("parameters") if isinstance(n.get("parameters"), dict) else {},
            credentials=n.get("credentials") if isinstance(n.get("credentials"), dict) else {},
        ))
    return ParsedTemplate("n8n", _str(data.get("name") or ""), nodes, source)


def _parse_dify(data: dict, source: str) -> ParsedTemplate:
    nodes = []
    for n in data["workflow"]["graph"]["nodes"]:
        if not isinstance(n, dict):
            continue
        d = n.get("data") if isinstance(n.get("data"), dict) else {}
        # The whole data block is the parameter surface (url, code, provider…).
        params = {k: v for k, v in d.items() if k not in ("type", "title")}
        nodes.append(TplNode(
            node_id=_str(n.get("id") or d.get("title") or "?"),
            name=_str(d.get("title") or n.get("id") or "?"),
            type=_str(d.get("type")),
            parameters=params,
        ))
    app = data.get("app") if isinstance(data.get("app"), dict) else {}
    return ParsedTemplate("dify", _str(app.get("name") or ""), nodes, source)


def _parse_flowise(data: dict, source: str) -> ParsedTemplate:
    fd = data["flowData"]
    if isinstance(fd, str):
        try:
            fd = json.loads(fd)
        except ValueError as exc:
            raise TemplateParseError(f"Flowise flowData is not valid JSON ({exc})")
    if not isinstance(fd, dict) or not isinstance(fd.get("nodes"), list):
        raise TemplateParseError(
            "Flowise flowData has no nodes[] — expected a flowData object or "
            "JSON string with nodes[]")
    nodes = []
    for n in fd["nodes"]:
        if not isinstance(n, dict):
            continue
        d = n.get("data") if isinstance(n.get("data"), dict) else {}
        nodes.append(TplNode(
            node_id=_str(n.get("id") or d.get("id") or "?"),
            name=_str(d.get("label") or d.get("name") or n.get("id") or "?"),
            type=_str(d.get("type") or d.get("name")),
            parameters=d.get("inputs") if isinstance(d.get("inputs"), dict) else {},
        ))
    return ParsedTemplate("flowise", _str(data.get("name") or ""), nodes, source)


# ---------------------------------------------------------------- helpers

def _is_placeholder(value: str) -> bool:
    """Expressions and obvious placeholders are not embedded secrets:
    '={{ $env.KEY }}', '{{#secret#}}', '${KEY}', 'YOUR_API_KEY', 'sk-XXXX…'."""
    v = value.strip()
    low = v.lower()
    if not v:
        return True
    if "{{" in v or "${" in v or "$env." in low or "process.env" in low:
        return True
    if re.search(r"x{4,}", low) or re.search(r"(^|[_\W])your[_-]", low):
        return True
    if re.fullmatch(r"<[^>]*>", v):
        return True
    return False


def _mask(secret: str) -> str:
    """Never print a secret: show just enough to locate it."""
    return secret[:4] + "…" + secret[-2:] if len(secret) > 6 else "…"


def _walk_strings(obj, path: str = ""):
    """Yield (json-path, string) for every string leaf in obj."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_strings(v, f"{path}[{i}]")


def _classify_host(host: str) -> str:
    """'allowlisted' | 'private' | 'public'."""
    h = host.rstrip(".").lower()
    if any(h == d or h.endswith("." + d) for d in KNOWN_SAAS_HOSTS):
        return "allowlisted"
    try:
        ip = ipaddress.ip_address(h)
        return "private" if (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast
        ) else "public"
    except ValueError:
        pass
    if h == "localhost" or h.endswith((".local", ".internal", ".lan", ".corp")):
        return "private"
    return "public"


def _outbound_urls(node: TplNode) -> list[str]:
    """URLs this node would call outbound, per ecosystem. Empty for node
    types that don't make outbound HTTP calls."""
    t = node.type.lower()
    urls: list[str] = []
    if ".httprequest" in t or t.endswith("http-request") or \
            node.type_suffix in ("http", "webhook"):
        u = node.parameters.get("url")
        if isinstance(u, str):
            urls.append(u)
    return urls


def _url_hosts(urls: list[str]):
    """Yield (url, host, class) for URLs whose host can be determined.
    Expression URLs ({{…}}) are skipped — the host is unknowable statically."""
    for u in urls:
        try:
            host = urlsplit(u).hostname
        except ValueError:
            continue
        if host:
            yield u, host, _classify_host(host)


# ---------------------------------------------------------------- rules

def rule_embedded_secrets(tpl: ParsedTemplate) -> list[Finding]:
    """Evidence rule: a string literal in a node's parameters matches a known
    token shape (sk-…, AKIA…, xox…, …), or sits under a secret-named key
    (password:, apiKey:) with a non-placeholder value; or a credentials block
    carries inline values beyond an id+name reference (a reference like
    {id, name: 'OpenAI account'} is NOT a secret); or a URL embeds userinfo
    or a token query parameter. Secrets are masked in evidence."""
    findings = []
    for node in tpl.nodes:
        for path, value in _walk_strings(node.parameters):
            if _is_placeholder(value):
                continue
            # shaped tokens (first pattern to hit a span wins)
            spans: list[tuple[int, int]] = []
            for label, rx in _SECRET_PATTERNS:
                for m in rx.finditer(value):
                    if any(s <= m.start() < e or s < m.end() <= e for s, e in spans):
                        continue
                    spans.append(m.span())
                    findings.append(_finding(
                        tpl, "template-embedded-secrets", "CRITICAL",
                        f"embedded secret in {node.label}",
                        f"{node.label} parameter {path!r} contains a literal "
                        f"matching {label} ({_mask(m.group(0))}) — templates "
                        "are shared files; whoever imports this gets the key"))
            if spans:
                continue
            # secret-named parameter keys with literal values
            key = path.rsplit(".", 1)[-1]
            key = re.sub(r"\[\d+\]$", "", key).lower()
            if key in _SENSITIVE_KEYS and len(value.strip()) >= 8:
                findings.append(_finding(
                    tpl, "template-embedded-secrets", "CRITICAL",
                    f"embedded secret in {node.label}",
                    f"{node.label} parameter {path!r} is a secret-named field "
                    f"with a literal value ({_mask(value.strip())})"))
            # URLs with userinfo or token query params
            for m in _URL_RE.finditer(value):
                try:
                    u = urlsplit(m.group(0))
                except ValueError:
                    continue
                if u.password and not _is_placeholder(u.password):
                    findings.append(_finding(
                        tpl, "template-embedded-secrets", "CRITICAL",
                        f"URL with embedded credentials in {node.label}",
                        f"{node.label} parameter {path!r} contains a URL with "
                        f"userinfo ({u.username}:***@{u.hostname}) — the "
                        "password travels with the template"))
                for qk, qv in parse_qsl(u.query):
                    if qk.lower() in _URL_TOKEN_PARAMS and qv \
                            and not _is_placeholder(qv) and len(qv) >= 6:
                        findings.append(_finding(
                            tpl, "template-embedded-secrets", "CRITICAL",
                            f"URL with embedded token in {node.label}",
                            f"{node.label} parameter {path!r} contains a URL "
                            f"with token query parameter {qk!r} "
                            f"({_mask(qv)})"))
        # credentials blocks: id+name is a reference (fine); any other
        # non-empty string value is an inline secret (not fine)
        for cred_type, cred in node.credentials.items():
            if not isinstance(cred, dict):
                continue
            inline = {k: v for k, v in cred.items()
                      if k not in ("id", "name")
                      and isinstance(v, str) and not _is_placeholder(v)}
            if inline:
                findings.append(_finding(
                    tpl, "template-embedded-secrets", "CRITICAL",
                    f"credentials block with inline values in {node.label}",
                    f"{node.label} credentials[{cred_type!r}] carries inline "
                    f"values for {sorted(inline)} — a credential REFERENCE is "
                    "id+name only; inline values are the secret itself"))
    return findings


def rule_unknown_outbound(tpl: ParsedTemplate) -> list[Finding]:
    """Evidence rule: an outbound-capable node (httpRequest / http-request /
    http / webhook with a URL) targets a host outside the known-SaaS seed
    allowlist → HIGH 'template phones home'. Localhost/private hosts are
    normal in internal tooling: noted at INFO, never graded. Allowlisted
    hosts produce no finding (FP guard)."""
    findings = []
    for node in tpl.nodes:
        for url, host, cls in _url_hosts(_outbound_urls(node)):
            if cls == "allowlisted":
                continue
            if cls == "private":
                findings.append(_finding(
                    tpl, "template-unknown-outbound", "INFO",
                    f"outbound call to private host in {node.label}",
                    f"{node.label} calls {url} — private/loopback host, normal "
                    "for internal tooling (noted, not graded)"))
            else:
                f = _finding(
                    tpl, "template-unknown-outbound", "HIGH",
                    f"template phones home to {host}",
                    f"{node.label} ({node.type or node.name}) sends data to "
                    f"{url} — host {host!r} is not on the known-SaaS allowlist; "
                    "verify this endpoint before importing")
                f.details["host"] = host
                findings.append(f)
    return findings


def rule_dangerous_execute(tpl: ParsedTemplate) -> list[Finding]:
    """Evidence rule: the node type executes arbitrary commands or code on
    the workflow host (executeCommand / ssh / shell / code) → HIGH, naming
    the node."""
    findings = []
    for node in tpl.nodes:
        if node.type_suffix in _DANGEROUS_SUFFIXES:
            findings.append(_finding(
                tpl, "template-dangerous-execute", "HIGH",
                f"dangerous execution node {node.name!r}",
                f"{node.label} is of type {node.type!r} — it runs arbitrary "
                "commands/code wherever the template is imported; review what "
                "it executes before enabling the workflow"))
    return findings


def rule_exfil_shape(tpl: ParsedTemplate) -> list[Finding]:
    """Evidence rule: the template BOTH reads data (sheets/docs, postgres,
    mysql, file read, knowledge retrieval) AND has an outbound HTTP node to a
    non-allowlisted PUBLIC host → CRITICAL. One half alone is not enough:
    data-read without unknown outbound, or unknown outbound without a data
    source, produces no exfil finding."""
    readers = []
    for node in tpl.nodes:
        if node.type_suffix in _DATA_READ_SUFFIXES:
            # readWriteFile with a write-only operation doesn't read anything
            op = str(node.parameters.get("operation") or "").lower()
            if "write" in op and "read" not in op:
                continue
            readers.append(node)
    sinks = []
    for node in tpl.nodes:
        for url, host, cls in _url_hosts(_outbound_urls(node)):
            if cls == "public":
                sinks.append((node, host))
                break
    if readers and sinks:
        r, (s, host) = readers[0], sinks[0]
        f = _finding(
            tpl, "template-exfil-shape", "CRITICAL",
            f"data-read + unknown-outbound = exfil shape ({r.name!r} → {host})",
            f"{r.label} reads data (type {r.type!r}) and {s.label} sends "
            f"outbound to non-allowlisted host {host!r} — the classic "
            "credential/data exfil template shape")
        f.details["host"] = host
        f.details["reader"] = r.name
        f.details["sink"] = s.name
        return [f]
    return []


def rule_unpinned_community(tpl: ParsedTemplate) -> list[Finding]:
    """Evidence rule: n8n nodes from non-first-party packages (community
    nodes are unpinned third-party code), or Dify tool nodes with a
    non-builtin / marketplace-scoped provider (author/name) → MEDIUM."""
    findings = []
    for node in tpl.nodes:
        if tpl.ecosystem == "n8n":
            if node.type and not node.type.startswith(_N8N_FIRST_PARTY_PREFIXES):
                pkg = node.type.split(".", 1)[0]
                findings.append(_finding(
                    tpl, "template-unpinned-community", "MEDIUM",
                    f"community node package {pkg!r} in {node.label}",
                    f"{node.label} uses {node.type!r} — a community node "
                    "package: third-party code, unpinned, not audited by n8n; "
                    "it runs with the instance's credentials"))
        elif tpl.ecosystem == "dify":
            if node.type != "tool":
                continue
            provider = str(node.parameters.get("provider_id") or "")
            ptype = str(node.parameters.get("provider_type") or "")
            if "/" in provider or (ptype and ptype != "builtin"):
                findings.append(_finding(
                    tpl, "template-unpinned-community", "MEDIUM",
                    f"unknown tool provider {provider or ptype!r} in {node.label}",
                    f"{node.label} uses tool provider "
                    f"{provider or ptype!r} — not a Dify builtin; third-party "
                    "tools run with the app's credentials"))
    return findings


RULES = (
    rule_embedded_secrets,
    rule_unknown_outbound,
    rule_dangerous_execute,
    rule_exfil_shape,
    rule_unpinned_community,
)

_FAIL_SEVERITIES = {"CRITICAL", "HIGH"}


def _finding(tpl: ParsedTemplate, check_id: str, severity: str,
             title: str, evidence: str) -> Finding:
    return Finding(
        check_id=check_id,
        product=f"{tpl.ecosystem}-template",
        title=title,
        severity=severity,
        url=tpl.source,
        evidence=evidence,
        fix_card_id=check_id,
        details={"node_rule": check_id, "template": tpl.name},
    )


def scan_template(tpl: ParsedTemplate) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(tpl))
    return findings


# ---------------------------------------------------------------- sources

def fetch_template_url(url: str,
                       transport: httpx.BaseTransport | None = None) -> str:
    """Fetch a template over https. Contract (the house redirect caution,
    same as recon._fetch): follow_redirects=False, redirects are followed
    only when they stay on the SAME host (a cross-host redirect would turn
    this into an open GET proxy), 1 MB cap, 10 s timeout."""
    if urlsplit(url).scheme != "https":
        raise TemplateFetchError(
            f"only https:// URLs are fetched, got {urlsplit(url).scheme!r}")
    cur = url
    with httpx.Client(transport=transport, timeout=FETCH_TIMEOUT,
                      follow_redirects=False) as client:
        for _hop in range(3):
            try:
                resp = client.get(cur)
            except httpx.HTTPError as exc:
                raise TemplateFetchError(f"fetch failed for {cur}: {exc}")
            if resp.status_code in _REDIRECT_STATUSES:
                loc = urljoin(cur, resp.headers.get("location", ""))
                nxt = urlsplit(loc)
                if (nxt.hostname or "").rstrip(".").lower() != \
                        (urlsplit(cur).hostname or "").rstrip(".").lower():
                    raise TemplateFetchError(
                        f"cross-host redirect blocked: {cur} → {loc}")
                if nxt.scheme != "https":
                    raise TemplateFetchError(
                        f"redirect to non-https blocked: {cur} → {loc}")
                cur = loc
                continue
            if resp.status_code != 200:
                raise TemplateFetchError(f"GET {cur} → {resp.status_code}")
            cl = resp.headers.get("content-length")
            if cl and cl.isdigit() and int(cl) > MAX_INPUT_BYTES:
                raise TemplateFetchError(
                    f"{cur} exceeds the {MAX_INPUT_BYTES}-byte cap "
                    f"(content-length {cl})")
            body = resp.content
            if len(body) > MAX_INPUT_BYTES:
                raise TemplateFetchError(
                    f"{cur} exceeds the {MAX_INPUT_BYTES}-byte cap "
                    f"({len(body)} bytes)")
            return body.decode("utf-8", "replace")
    raise TemplateFetchError(f"too many redirects fetching {url}")


def read_source(src: str,
                transport: httpx.BaseTransport | None = None) -> str:
    """File path or https URL → template text."""
    if src.startswith(("http://", "https://")):
        return fetch_template_url(src, transport=transport)
    p = Path(src)
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise TemplateFetchError(f"cannot read {src}: {exc}")
    if size > MAX_INPUT_BYTES:
        raise TemplateFetchError(
            f"{src} exceeds the {MAX_INPUT_BYTES}-byte cap ({size} bytes)")
    return p.read_text(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------- CLI

def _summary(findings: list[dict]) -> dict:
    counts = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "INFO")}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return {k: v for k, v in counts.items() if v}


def render_text(results: list[dict]) -> str:
    lines: list[str] = []
    for r in results:
        src = r["source"]
        if "error" in r:
            lines.append(f"aicheck template — {src} → ERROR: {r['error']}")
            continue
        findings = r["findings"]
        summary = r["summary"]
        bits = ", ".join(f"{n} {s}" for s, n in summary.items()) or "clean"
        name = f" {r['name']!r}" if r.get("name") else ""
        lines.append(
            f"aicheck template — {src} → {r['ecosystem']}{name} "
            f"({len(findings)} findings: {bits})")
        for f in findings:
            lines.append(f"  {f['severity']:8} {f['check_id']}: {f['title']}")
            lines.append(f"           evidence: {f['evidence']}")
        if not findings:
            lines.append("  clean — no template findings")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None,
         transport: httpx.BaseTransport | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="aicheck template",
        description="Static security scan of AI workflow templates "
                    "(n8n / Dify / Flowise) — files, not live targets.")
    ap.add_argument("sources", nargs="+",
                    help="template file paths or https URLs (N allowed)")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--version", action="version",
                    version=f"%(prog)s {_version()}")
    args = ap.parse_args(argv)

    results: list[dict] = []
    any_error = False
    for src in args.sources:
        try:
            text = read_source(src, transport=transport)
            tpl = parse_template(text, source=src)
            findings = [f.to_dict() for f in scan_template(tpl)]
            results.append({
                "source": src,
                "ecosystem": tpl.ecosystem,
                "name": tpl.name,
                "summary": _summary(findings),
                "findings": findings,
            })
        except (TemplateFetchError, TemplateParseError) as exc:
            any_error = True
            print(f"error: {src}: {exc}", file=sys.stderr)
            results.append({"source": src, "error": str(exc)})
        except Exception as exc:  # engine error — never report as clean
            any_error = True
            print(f"aicheck template engine error: "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr)
            results.append({"source": src,
                            "error": f"{type(exc).__name__}: {exc}"})

    if args.format == "json":
        payload = results[0] if len(results) == 1 else {"results": results}
        print(json.dumps(payload, indent=2))
    else:
        print(render_text(results), end="")

    if any_error:
        return 2
    worst = {f["severity"] for r in results if "findings" in r
             for f in r["findings"]}
    return 1 if worst & _FAIL_SEVERITIES else 0


def _version() -> str:
    from . import __version__
    return __version__


if __name__ == "__main__":
    sys.exit(main())
