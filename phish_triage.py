#!/usr/bin/env python3
"""
phish_triage.py — Phishing triage + IOC extraction (single + batch) for Linux SOC-style workflows.

Key features:
- URL extraction + deobfuscation (hxxp, [.] etc)
- URL scoring (shorteners, IP hosts, punycode, suspicious TLDs, login keywords, etc.)
- Brand impersonation detection (keyword + typosquatting)
- Simple social-engineering language heuristics (urgency/credential/threat)
- Auth header parsing summary (SPF/DKIM/DMARC presence + basic alignment hints)
- Attachment inventory + hashing + basic filename risk rules
- Batch mode with optional parallel processing
- Campaign correlation (clusters by shared IOCs)
- Optional threat-intel enrichment: URLhaus (free), VirusTotal, AbuseIPDB (keys)

Outputs:
- Per email: report.json, report.md, iocs.csv
- Batch: batch_summary.json, batch_results.json, batch_campaigns.json (+ enrichment caches if enabled)

Dependencies (recommended):
  pip install pyyaml requests
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore


# ----------------------------
# Defaults / Config
# ----------------------------

DEFAULT_CONFIG = {
    "general": {
        "outdir": "outputs",
        "parallel": True,
        "workers": 4,
        "timeout_seconds": 10,
        "formats": ["json", "csv", "markdown"],
    },
    "scoring": {
        "thresholds": {"phish": 12, "suspicious": 7},
        "require_two_categories_for_phish": True,
    },
    "brands": {
        "domains": [
            "paypal.com",
            "amazon.com",
            "microsoft.com",
            "apple.com",
            "google.com",
            "facebook.com",
            "netflix.com",
            "chase.com",
            "wellsfargo.com",
            "bankofamerica.com",
            "dhl.com",
            "fedex.com",
        ]
    },
    "threat_intel": {
        "urlhaus": {"enabled": True},
        "virustotal": {"enabled": False, "api_key_env": "VT_API_KEY", "rpm": 4},
        "abuseipdb": {"enabled": False, "api_key_env": "ABUSEIPDB_API_KEY", "rpm": 10},
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base (does not mutate inputs)."""
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str = "config.yaml") -> dict:
    if not path:
        return dict(DEFAULT_CONFIG)
    if not os.path.exists(path):
        return dict(DEFAULT_CONFIG)
    if yaml is None:
        # YAML not available; fall back to defaults.
        return dict(DEFAULT_CONFIG)
    with open(path, "r", encoding="utf-8") as f:
        parsed = yaml.safe_load(f) or {}
    return deep_merge(DEFAULT_CONFIG, parsed)


# ----------------------------
# Logging
# ----------------------------

def setup_logging(outdir: str, level: int = logging.INFO) -> logging.Logger:
    os.makedirs(outdir, exist_ok=True)
    log_path = os.path.join(outdir, "phish_triage.log")

    logger = logging.getLogger("phish_triage")
    logger.setLevel(level)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    fh = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=3)
    fh.setFormatter(fmt)
    fh.setLevel(level)

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    sh.setLevel(level)

    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger


# ----------------------------
# Utilities
# ----------------------------

URL_REGEX = re.compile(r'(?i)\b((?:https?://|hxxps?://|www\.)[^\s<>"\']+)')
HREF_REGEX = re.compile(r'(?i)href\s*=\s*["\']([^"\']+)["\']')

TRAILING_PUNCT = '.,);:!?\'"\\]}>'

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "rb.gy", "bitly.com",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "icu", "click", "work", "monster", "support", "rest",
    "ru", "cn", "tk", "zip", "mov",
}

DANGEROUS_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".vbs", ".js", ".jar", ".ps1", ".hta", ".msi", ".lnk", ".iso",
}


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sanitize_md(s: str) -> str:
    """Escape common markdown special chars to keep reports readable."""
    if s is None:
        return ""
    s = s.replace("\\", "\\\\")
    s = s.replace("`", "\\`")
    s = s.replace("|", "\\|")
    s = s.replace("*", "\\*")
    s = s.replace("_", "\\_")
    s = s.replace("<", "\\<").replace(">", "\\>")
    return s


def shorten_one_line(s: str, n: int = 260) -> str:
    s = re.sub(r"\s+", " ", s or "").strip()
    if len(s) <= n:
        return s
    return s[: n - 3] + "..."


def deobfuscate(s: str) -> str:
    """Convert common obfuscations used in phishing writeups/emails to standard form."""
    if not s:
        return ""
    s = s.replace("hxxps://", "https://").replace("hxxp://", "http://")
    s = s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    s = s.replace("[:]//", "://").replace("[://]", "://")
    s = s.replace("[at]", "@").replace("(at)", "@")
    # Some emails use spaces around dots
    s = re.sub(r"\s*\.\s*", ".", s)
    return s


def normalise_url(raw: str) -> str:
    u = deobfuscate((raw or "").strip())

    # Strip surrounding angle brackets etc.
    u = u.strip("<>")

    # Remove trailing punctuation that often clings to URLs
    while u and u[-1] in TRAILING_PUNCT:
        u = u[:-1]

    # Prepend scheme if only www.
    if u.lower().startswith("www."):
        u = "http://" + u

    # Clean whitespace
    u = re.sub(r"\s+", "", u)

    # Basic parse/repair
    try:
        p = urlparse(u)
        if not p.scheme:
            p = urlparse("http://" + u)
        # Normalize netloc casing
        netloc = (p.netloc or "").strip().lower()
        path = p.path or ""
        # Avoid accidental empty netloc from malformed URL like http:example.com
        if not netloc and p.path and p.scheme:
            # Attempt repair: scheme:example.com/path -> scheme://example.com/path
            repaired = f"{p.scheme}://{p.path}"
            p2 = urlparse(repaired)
            netloc = (p2.netloc or "").lower()
            path = p2.path or ""
            p = p2._replace(netloc=netloc, path=path)
        return urlunparse(p._replace(netloc=netloc))
    except Exception:
        return u


def extract_urls(text: str) -> List[str]:
    text = deobfuscate(text or "")
    urls: Set[str] = set()

    for m in URL_REGEX.findall(text):
        urls.add(normalise_url(m))
    for m in HREF_REGEX.findall(text):
        urls.add(normalise_url(m))

    cleaned = []
    for u in urls:
        if u.lower().startswith(("http://", "https://")):
            cleaned.append(u)
    return sorted(set(cleaned))


def domain_from_url(u: str) -> str:
    try:
        p = urlparse(u if "://" in u else "http://" + u)
        host = (p.netloc or "").split("@")[-1]
        host = host.split(":")[0].strip(".").lower()
        return host
    except Exception:
        return ""


def header_email_domain(header_value: str) -> str:
    """Extract domain from From/Reply-To/Return-Path header."""
    if not header_value:
        return ""
    m = re.search(r"<([^>]+)>", header_value)
    addr = m.group(1) if m else header_value
    addr = addr.strip().strip('"').strip()
    # Remove any name portion
    if "@" in addr:
        return addr.split("@")[-1].strip(">").strip().lower()
    return ""


def base_domain(domain: str) -> str:
    """Simple base domain extractor: last two labels (demo-grade)."""
    parts = [p for p in (domain or "").lower().split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.lower().strip(".")


def levenshtein(a: str, b: str) -> int:
    """Small Levenshtein distance implementation (good enough for short domains)."""
    a, b = a or "", b or ""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    # Ensure a is shorter
    if len(a) > len(b):
        a, b = b, a
    prev = list(range(len(a) + 1))
    for i, cb in enumerate(b, 1):
        cur = [i]
        for j, ca in enumerate(a, 1):
            ins = cur[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (0 if ca == cb else 1)
            cur.append(min(ins, dele, sub))
        prev = cur
    return prev[-1]


def normalize_homoglyph_ascii(s: str) -> str:
    """Heuristic: normalize common ASCII lookalikes (not full Unicode confusables)."""
    if not s:
        return ""
    table = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t",
        "|": "l",
        "¡": "i",
        "Ι": "I",  # Greek Iota-ish
    })
    return s.translate(table)


def detect_brand_impersonation(domains: Set[str], config: dict) -> Tuple[int, List[str]]:
    brand_list = set((config.get("brands", {}) or {}).get("domains", []) or [])
    if not domains or not brand_list:
        return 0, []

    score = 0
    notes: List[str] = []

    brand_bases = {base_domain(b): b for b in brand_list}

    for d in domains:
        d = d.lower()
        d_base = base_domain(d)
        d_base_norm = normalize_homoglyph_ascii(d_base)

        # Keyword-in-domain but not the real domain
        for brand_base, _full in brand_bases.items():
            brand_key = brand_base.split(".")[0]
            if brand_key and brand_key in d and d_base != brand_base:
                score += 4
                notes.append(f"brand_keyword:{brand_key}:{d}")

        # Typosquat similarity vs brand base (on base domains)
        for brand_base, _full in brand_bases.items():
            if d_base == brand_base:
                continue
            dist = levenshtein(d_base_norm, normalize_homoglyph_ascii(brand_base))
            if dist == 1:
                score += 6
                notes.append(f"typosquat:{d_base}~{brand_base}:dist1")
            elif dist == 2:
                score += 3
                notes.append(f"typosquat:{d_base}~{brand_base}:dist2")

        # Punycode present is suspicious; brand sometimes punycodes to mimic
        if d.startswith("xn--") or ".xn--" in d:
            score += 2
            notes.append(f"punycode_domain:{d}")

    return score, notes


# ----------------------------
# Scoring
# ----------------------------

def score_url(u: str) -> Tuple[int, List[str]]:
    score = 0
    notes: List[str] = []
    host = domain_from_url(u)

    # '@' in URL can hide real host
    if "@" in u:
        score += 2
        notes.append("at_symbol")

    # IP host (often malicious, but can be internal)
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or ""):
        score += 4
        notes.append("ip_host")

    # URL shorteners
    if host in SHORTENERS:
        score += 3
        notes.append("shortener")

    # IDNA / punycode
    if host.startswith("xn--") or ".xn--" in host:
        score += 3
        notes.append("punycode")

    # TLD risk
    tld = (host.split(".")[-1] if host and "." in host else "")
    if tld in SUSPICIOUS_TLDS:
        score += 2
        notes.append(f"suspicious_tld:{tld}")

    # Non-HTTPS
    if u.lower().startswith("http://"):
        score += 1
        notes.append("non_https")

    # Length + subdomains
    if len(u) > 120:
        score += 2
        notes.append("very_long_url")
    elif len(u) > 75:
        score += 1
        notes.append("long_url")

    if host:
        sub_ct = host.count(".")
        if sub_ct >= 3:
            score += 1
            notes.append("many_subdomains")

    # Path keywords
    lower = u.lower()
    if any(k in lower for k in ["login", "signin", "verify", "update", "secure", "account", "password"]):
        score += 2
        notes.append("phish_keywords")

    return score, notes


# ----------------------------
# Content heuristics
# ----------------------------

URGENCY_PATTERNS = [
    r"(?i)immediate(ly)?\s+action",
    r"(?i)within\s+\d+\s+(hours?|days?)",
    r"(?i)urgent|emergency|critical",
    r"(?i)final\s+(warning|notice|reminder)",
    r"(?i)expire(d|s)?\s+(today|soon|shortly)",
]
CRED_PATTERNS = [
    r"(?i)verify\s+your\s+(account|identity|information)",
    r"(?i)(confirm|update|validate)\s+your\s+(password|details)",
    r"(?i)click\s+(here|below)\s+to\s+(log\s*in|sign\s*in)",
    r"(?i)re-?enter\s+your\s+(username|password)",
]
THREAT_PATTERNS = [
    r"(?i)(lose\s+access|account\s+closure|permanent\s+deletion)",
    r"(?i)legal\s+action",
    r"(?i)unauthorized\s+(access|activity|transaction)",
    r"(?i)account\s+(will\s+be\s+)?(suspended|closed|locked)",
]


def analyze_content(text: str, subject: str) -> Tuple[int, List[str]]:
    combined = f"{subject}\n{text}"
    score = 0
    notes: List[str] = []

    urgency = sum(1 for p in URGENCY_PATTERNS if re.search(p, combined))
    if urgency >= 2:
        score += 3
        notes.append(f"urgency_language:{urgency}")

    cred = sum(1 for p in CRED_PATTERNS if re.search(p, combined))
    if cred >= 1:
        score += 4
        notes.append("credential_request")

    threat = sum(1 for p in THREAT_PATTERNS if re.search(p, combined))
    if threat >= 1:
        score += 2
        notes.append("threat_language")

    if re.search(r"(?im)^(dear|hello)\s+(customer|user|member|sir|madam)\b", combined.strip()):
        score += 2
        notes.append("generic_greeting")

    return score, notes


# ----------------------------
# Email parsing
# ----------------------------

def read_eml(path: str):
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def strip_html(html: str) -> str:
    # minimal HTML to text (keep it simple + safe)
    html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    html = re.sub(r"(?is)<br\s*/?>", "\n", html)
    html = re.sub(r"(?is)</p\s*>", "\n", html)
    html = re.sub(r"(?is)<[^>]+>", " ", html)
    html = re.sub(r"&nbsp;", " ", html)
    html = re.sub(r"\s+", " ", html)
    return html.strip()


def get_text_parts(msg) -> str:
    parts: List[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    payload = part.get_content()
                except Exception:
                    payload = part.get_payload(decode=True)
                    if isinstance(payload, bytes):
                        payload = payload.decode(errors="replace")
                if not payload:
                    continue
                if ctype == "text/html":
                    payload = strip_html(str(payload))
                parts.append(str(payload))
    else:
        try:
            payload = msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode(errors="replace")
        if payload:
            parts.append(str(payload))
    return "\n\n".join(parts)


# ----------------------------
# Attachments
# ----------------------------

def analyze_attachment(filename: str, payload: bytes, content_type: str) -> Tuple[int, List[str]]:
    score = 0
    notes: List[str] = []

    fn = filename or "unknown"
    lower = fn.lower()
    ext = Path(lower).suffix

    if ext in DANGEROUS_EXTS:
        score += 10
        notes.append(f"dangerous_extension:{ext}")

    if lower.count(".") >= 2:
        score += 3
        notes.append("double_extension")

    # Common archive evasion
    if ext in {".zip", ".rar", ".7z"}:
        score += 2
        notes.append("archive_attachment")

    # Very large attachment (can be suspicious)
    if payload and len(payload) > 5_000_000:
        score += 1
        notes.append("large_attachment")

    return score, notes


def extract_attachments(msg) -> List[dict]:
    atts: List[dict] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disp = str(part.get("Content-Disposition", "")).lower()
        # include attachments OR inline with filename
        if ("attachment" in disp) or filename:
            payload = part.get_payload(decode=True) or b""
            content_type = part.get_content_type()
            risk_score, risk_notes = analyze_attachment(filename or "unknown", payload, content_type)
            atts.append({
                "filename": filename or "unknown",
                "sha256": sha256_bytes(payload),
                "size_bytes": len(payload),
                "content_type": content_type,
                "risk_score": risk_score,
                "risk_notes": risk_notes,
            })
    return atts


# ----------------------------
# Auth headers (basic)
# ----------------------------

def get_auth_headers(msg) -> dict:
    keys = ["Authentication-Results", "ARC-Authentication-Results", "Received-SPF"]
    out = {}
    for k in keys:
        v = msg.get(k)
        out[k] = shorten_one_line(str(v)) if v else ""
    return out


def parse_auth_results(auth_header_value: str) -> dict:
    s = auth_header_value or ""
    # Example: dkim=pass header.i=@example.com; spf=pass smtp.mailfrom=example.com; dmarc=fail ...
    def pick(pattern: str) -> Optional[str]:
        m = re.search(pattern, s, flags=re.I)
        return m.group(1) if m else None

    dkim_res = pick(r"dkim=(pass|fail|none|neutral|temperror|permerror)")
    spf_res = pick(r"spf=(pass|fail|none|neutral|softfail|temperror|permerror)")
    dmarc_res = pick(r"dmarc=(pass|fail|bestguesspass|none)")
    dkim_dom = pick(r"header\.i=@?([A-Za-z0-9\.-]+)")
    spf_dom = pick(r"smtp\.mailfrom=([A-Za-z0-9\.-]+)")

    return {
        "dkim_result": (dkim_res or "").lower(),
        "dkim_domain": (dkim_dom or "").lower(),
        "spf_result": (spf_res or "").lower(),
        "spf_domain": (spf_dom or "").lower(),
        "dmarc_result": (dmarc_res or "").lower(),
    }


def auth_pass_summary(auth_meta: dict) -> dict:
    joined = " ".join(v for v in auth_meta.values() if v)
    joined = joined.lower()
    return {
        "spf_pass": "spf=pass" in joined,
        "dkim_pass": "dkim=pass" in joined,
        "dmarc_pass": "dmarc=pass" in joined,
    }


def auth_alignment_hints(from_domain: str, auth_meta: dict) -> dict:
    # Take Authentication-Results if available
    ar = auth_meta.get("Authentication-Results") or auth_meta.get("ARC-Authentication-Results") or ""
    parsed = parse_auth_results(ar)
    dkim_aligned = bool(from_domain and parsed.get("dkim_domain") and from_domain.endswith(parsed["dkim_domain"]))
    spf_aligned = bool(from_domain and parsed.get("spf_domain") and from_domain.endswith(parsed["spf_domain"]))
    return {
        **parsed,
        "from_domain": from_domain,
        "dkim_aligned": dkim_aligned,
        "spf_aligned": spf_aligned,
    }


# ----------------------------
# Verdict
# ----------------------------

def decide_verdict_v2(
    url_rows: List[dict],
    attachments: List[dict],
    from_reply_mismatch: bool,
    returnpath_mismatch: bool,
    auth_meta: dict,
    brand_notes: List[str],
    content_notes: List[str],
    total_score: int,
    config: dict,
    intel_notes: Optional[List[str]] = None,
) -> Tuple[str, str, List[str]]:

    thresholds = (config.get("scoring", {}) or {}).get("thresholds", {"phish": 12, "suspicious": 7})
    require_two = bool((config.get("scoring", {}) or {}).get("require_two_categories_for_phish", True))

    categories = set()
    if any(r["score"] >= 4 for r in url_rows): categories.add("url")
    if from_reply_mismatch or returnpath_mismatch: categories.add("header")
    if any(a.get("risk_score", 0) >= 3 for a in attachments): categories.add("attachment")
    if brand_notes: categories.add("brand")
    if content_notes: categories.add("content")
    if intel_notes: categories.add("intel")

    reasons: List[str] = []
    # keep reasons short and useful
    for r in url_rows:
        if r["score"] >= 4:
            reasons.append(f"url:{','.join(r['notes'])}")
            if len(reasons) >= 3: break
    reasons += brand_notes[:3]
    reasons += content_notes[:3]
    if from_reply_mismatch:
        reasons.append("from_reply_to_domain_mismatch")
    if returnpath_mismatch:
        reasons.append("return_path_from_domain_mismatch")
    if any(a.get("risk_score", 0) > 0 for a in attachments):
        reasons.append("attachment_present")
    if intel_notes:
        reasons += intel_notes[:3]

    auth = auth_pass_summary(auth_meta)
    all_auth_pass = auth["spf_pass"] and auth["dkim_pass"] and auth["dmarc_pass"]

    verdict = "Needs Review"
    confidence = "Low"

    if total_score >= thresholds["phish"]:
        if (not require_two) or (len(categories) >= 2):
            verdict = "Phish"
            confidence = "High"
        else:
            verdict = "Suspicious"
            confidence = "Medium"
    elif total_score >= thresholds["suspicious"]:
        verdict = "Suspicious"
        confidence = "Medium"

    # Auth passes reduce spoofing likelihood; don't override strong malicious signals, just reduce confidence
    if all_auth_pass and confidence == "High" and verdict != "Phish":
        confidence = "Medium"

    if not reasons:
        reasons = ["insufficient_indicators"]

    return verdict, confidence, reasons


# ----------------------------
# Exporters
# ----------------------------

def export_json(result: dict, outpath: str):
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)


def export_iocs_csv(rows: List[dict], outpath: str):
    with open(outpath, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["type", "value", "score", "notes"])
        w.writeheader()
        for r in rows:
            w.writerow({
                "type": r.get("type", ""),
                "value": r.get("value", ""),
                "score": r.get("score", 0),
                "notes": ",".join(r.get("notes", []) or []),
            })


def build_markdown_report(result: dict) -> str:
    meta = result.get("meta", {})
    auth = result.get("auth", {})
    align = result.get("auth_alignment", {})
    verdict = result.get("verdict", "Needs Review")
    confidence = result.get("confidence", "Low")
    score = result.get("score", 0)
    reasons = result.get("reasons", [])

    urls = result.get("urls", [])
    url_rows = result.get("url_rows", [])
    attachments = result.get("attachments", [])
    iocs = result.get("iocs", {})

    lines = []
    lines.append("# 🛡️ Phish Triage Report\n")
    lines.append(f"**Verdict:** `{sanitize_md(verdict)}`  \n")
    lines.append(f"**Confidence:** `{sanitize_md(confidence)}`  \n")
    lines.append(f"**Risk Score:** `{score}`  \n")
    lines.append("**Reasons:**\n")
    for r in reasons:
        lines.append(f"- {sanitize_md(str(r))}")
    lines.append("")

    lines.append("## Message Metadata\n")
    for k in ["subject", "from", "reply_to", "date", "from_domain", "reply_domain", "return_path", "return_path_domain"]:
        if k in meta:
            lines.append(f"- **{k}**: {sanitize_md(str(meta.get(k,'')))}")
    lines.append("")

    lines.append("## Authentication\n")
    for k, v in auth.items():
        lines.append(f"- **{k}**: {sanitize_md(str(v) or '(missing)')}")
    if align:
        lines.append("")
        lines.append("**Alignment hints:**")
        lines.append(f"- from_domain: `{sanitize_md(align.get('from_domain',''))}`")
        lines.append(f"- spf_result: `{sanitize_md(align.get('spf_result',''))}` spf_domain: `{sanitize_md(align.get('spf_domain',''))}` aligned: `{align.get('spf_aligned')}`")
        lines.append(f"- dkim_result: `{sanitize_md(align.get('dkim_result',''))}` dkim_domain: `{sanitize_md(align.get('dkim_domain',''))}` aligned: `{align.get('dkim_aligned')}`")
        lines.append(f"- dmarc_result: `{sanitize_md(align.get('dmarc_result',''))}`")
    lines.append("")

    lines.append(f"## URLs ({len(urls)})\n")
    if not urls:
        lines.append("_None found._\n")
    else:
        lines.append("| URL | Score | Notes |")
        lines.append("|---|---:|---|")
        for r in url_rows:
            lines.append(f"| `{sanitize_md(r['value'])}` | {r['score']} | {sanitize_md(','.join(r['notes']))} |")
        lines.append("")

    lines.append(f"## Attachments ({len(attachments)})\n")
    if not attachments:
        lines.append("_None found._\n")
    else:
        lines.append("| Filename | Type | Size | SHA256 | Risk | Notes |")
        lines.append("|---|---|---:|---|---:|---|")
        for a in attachments:
            lines.append(
                f"| `{sanitize_md(a.get('filename',''))}` | `{sanitize_md(a.get('content_type',''))}` | "
                f"{a.get('size_bytes',0)} | `{a.get('sha256','')}` | {a.get('risk_score',0)} | {sanitize_md(','.join(a.get('risk_notes',[]) or []))} |"
            )
        lines.append("")

    lines.append("## IOC Summary\n")
    lines.append(f"- Domains: {len(iocs.get('domains',[]))}")
    lines.append(f"- IPs: {len(iocs.get('ips',[]))}")
    lines.append(f"- URLs: {len(iocs.get('urls',[]))}")
    lines.append(f"- Attachment hashes: {len(iocs.get('sha256',[]))}")
    lines.append("")
    return "\n".join(lines)


def export_markdown(result: dict, outpath: str):
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(build_markdown_report(result))


# ----------------------------
# Threat intel enrichment
# ----------------------------

def ensure_requests():
    if requests is None:
        raise RuntimeError("requests is required for enrichment. Install: pip install requests")


def urlhaus_lookup(url: str, timeout: int = 10) -> dict:
    ensure_requests()
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        r = requests.post(endpoint, data={"url": url}, timeout=timeout)
        if r.status_code != 200:
            return {"ok": False, "error": f"status:{r.status_code}"}
        return {"ok": True, "data": r.json()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def vt_url_id(url: str) -> str:
    # VT v3 URL identifier is urlsafe b64 without '=' padding
    b = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")
    return b


def virustotal_lookup_url(url: str, api_key: str, timeout: int = 10) -> dict:
    ensure_requests()
    url_id = vt_url_id(url)
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(endpoint, headers=headers, timeout=timeout)
        if r.status_code != 200:
            return {"ok": False, "error": f"status:{r.status_code}", "text": shorten_one_line(r.text, 200)}
        return {"ok": True, "data": r.json()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def virustotal_lookup_file_hash(sha256: str, api_key: str, timeout: int = 10) -> dict:
    ensure_requests()
    endpoint = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(endpoint, headers=headers, timeout=timeout)
        if r.status_code != 200:
            return {"ok": False, "error": f"status:{r.status_code}", "text": shorten_one_line(r.text, 200)}
        return {"ok": True, "data": r.json()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def abuseipdb_lookup(ip: str, api_key: str, timeout: int = 10) -> dict:
    ensure_requests()
    endpoint = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        r = requests.get(endpoint, headers=headers, params=params, timeout=timeout)
        if r.status_code != 200:
            return {"ok": False, "error": f"status:{r.status_code}", "text": shorten_one_line(r.text, 200)}
        return {"ok": True, "data": r.json()}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def rate_limit_sleep(last_ts: float, rpm: int) -> float:
    if rpm <= 0:
        return time.time()
    min_interval = 60.0 / rpm
    now = time.time()
    wait = (last_ts + min_interval) - now
    if wait > 0:
        time.sleep(wait)
    return time.time()


def load_cache(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(path: str, obj: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def enrich_batch(results: List[dict], outdir: str, config: dict, providers: List[str], logger: logging.Logger) -> Tuple[List[dict], List[str]]:
    """Enrich deduped IOCs (sequential) and attach lightweight notes to each email result."""
    cache_path = os.path.join(outdir, ".cache", "enrichment.json")
    cache = load_cache(cache_path)

    timeout = int((config.get("general", {}) or {}).get("timeout_seconds", 10))
    ti = config.get("threat_intel", {}) or {}

    # Dedupe IOCs
    all_urls: Set[str] = set()
    all_ips: Set[str] = set()
    all_hashes: Set[str] = set()

    for r in results:
        iocs = r.get("iocs", {}) or {}
        for u in iocs.get("urls", []) or []:
            all_urls.add(u)
        for ip in iocs.get("ips", []) or []:
            all_ips.add(ip)
        for h in iocs.get("sha256", []) or []:
            all_hashes.add(h)

    enriched = {"urls": {}, "ips": {}, "sha256": {}}
    intel_notes: List[str] = []

    # URLhaus
    if "urlhaus" in providers and (ti.get("urlhaus", {}) or {}).get("enabled", True):
        last = 0.0
        for u in sorted(all_urls):
            key = f"urlhaus:url:{u}"
            if key in cache:
                enriched["urls"][u] = cache[key]
                continue
            logger.info(f"URLhaus lookup: {u}")
            res = urlhaus_lookup(u, timeout=timeout)
            cache[key] = res
            enriched["urls"][u] = res
            save_cache(cache_path, cache)

            # small notes if malicious
            if res.get("ok") and isinstance(res.get("data"), dict):
                if res["data"].get("query_status") == "ok":
                    intel_notes.append("urlhaus_hit")

    # VirusTotal
    if "virustotal" in providers and (ti.get("virustotal", {}) or {}).get("enabled", False):
        api_env = (ti.get("virustotal", {}) or {}).get("api_key_env", "VT_API_KEY")
        api_key = os.getenv(api_env, "")
        if not api_key:
            logger.warning("VirusTotal enabled but API key missing. Set env: %s", api_env)
        else:
            rpm = int((ti.get("virustotal", {}) or {}).get("rpm", 4))
            last = 0.0
            # URLs
            for u in sorted(all_urls):
                key = f"vt:url:{u}"
                if key in cache:
                    enriched["urls"][u] = cache[key]
                    continue
                last = rate_limit_sleep(last, rpm)
                logger.info(f"VirusTotal URL lookup: {u}")
                res = virustotal_lookup_url(u, api_key, timeout=timeout)
                cache[key] = res
                enriched["urls"][u] = res
                save_cache(cache_path, cache)
                if res.get("ok"):
                    stats = (((res.get("data") or {}).get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
                    if stats.get("malicious", 0) > 0:
                        intel_notes.append("virustotal_malicious_url")
            # File hashes
            for h in sorted(all_hashes):
                key = f"vt:file:{h}"
                if key in cache:
                    enriched["sha256"][h] = cache[key]
                    continue
                last = rate_limit_sleep(last, rpm)
                logger.info(f"VirusTotal file lookup: {h}")
                res = virustotal_lookup_file_hash(h, api_key, timeout=timeout)
                cache[key] = res
                enriched["sha256"][h] = res
                save_cache(cache_path, cache)
                if res.get("ok"):
                    stats = (((res.get("data") or {}).get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
                    if stats.get("malicious", 0) > 0:
                        intel_notes.append("virustotal_malicious_file")

    # AbuseIPDB
    if "abuseipdb" in providers and (ti.get("abuseipdb", {}) or {}).get("enabled", False):
        api_env = (ti.get("abuseipdb", {}) or {}).get("api_key_env", "ABUSEIPDB_API_KEY")
        api_key = os.getenv(api_env, "")
        if not api_key:
            logger.warning("AbuseIPDB enabled but API key missing. Set env: %s", api_env)
        else:
            rpm = int((ti.get("abuseipdb", {}) or {}).get("rpm", 10))
            last = 0.0
            for ip in sorted(all_ips):
                key = f"abuseipdb:ip:{ip}"
                if key in cache:
                    enriched["ips"][ip] = cache[key]
                    continue
                last = rate_limit_sleep(last, rpm)
                logger.info(f"AbuseIPDB lookup: {ip}")
                res = abuseipdb_lookup(ip, api_key, timeout=timeout)
                cache[key] = res
                enriched["ips"][ip] = res
                save_cache(cache_path, cache)
                if res.get("ok"):
                    data = ((res.get("data") or {}).get("data") or {})
                    if data.get("abuseConfidenceScore", 0) >= 50:
                        intel_notes.append("abuseipdb_high_confidence")

    # Attach enrichment to each email result (lightweight)
    for r in results:
        iocs = r.get("iocs", {}) or {}
        r["enrichment"] = {"urls": {}, "ips": {}, "sha256": {}}
        for u in iocs.get("urls", []) or []:
            if u in enriched["urls"]:
                r["enrichment"]["urls"][u] = enriched["urls"][u]
        for ip in iocs.get("ips", []) or []:
            if ip in enriched["ips"]:
                r["enrichment"]["ips"][ip] = enriched["ips"][ip]
        for h in iocs.get("sha256", []) or []:
            if h in enriched["sha256"]:
                r["enrichment"]["sha256"][h] = enriched["sha256"][h]

    with open(os.path.join(outdir, "batch_enrichment.json"), "w", encoding="utf-8") as f:
        json.dump(enriched, f, indent=2)

    # Reduce to unique intel notes
    intel_notes = sorted(set(intel_notes))
    return results, intel_notes


# ----------------------------
# Campaign correlation (union-find)
# ----------------------------

class UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            self.parent[ra] = rb
        elif self.rank[ra] > self.rank[rb]:
            self.parent[rb] = ra
        else:
            self.parent[rb] = ra
            self.rank[ra] += 1


def parse_email_date(date_str: str) -> Optional[str]:
    try:
        dt = parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return None


def build_campaigns(batch_results: List[dict]) -> List[dict]:
    n = len(batch_results)
    uf = UnionFind(n)

    ind_map: Dict[str, List[int]] = {}

    for idx, r in enumerate(batch_results):
        i = r.get("iocs", {}) or {}
        inds = set()
        inds |= {f"domain:{d}" for d in i.get("domains", []) or []}
        inds |= {f"ip:{ip}" for ip in i.get("ips", []) or []}
        inds |= {f"sha256:{h}" for h in i.get("sha256", []) or []}
        for ind in inds:
            ind_map.setdefault(ind, []).append(idx)

    # Union emails that share any indicator
    for ind, idxs in ind_map.items():
        if len(idxs) < 2:
            continue
        first = idxs[0]
        for other in idxs[1:]:
            uf.union(first, other)

    # Group by root
    groups: Dict[int, List[int]] = {}
    for i in range(n):
        root = uf.find(i)
        groups.setdefault(root, []).append(i)

    campaigns = []
    camp_num = 1
    for _, idxs in groups.items():
        # ignore groups with no indicators
        comp_inds = set()
        dates = []
        for idx in idxs:
            i = batch_results[idx].get("iocs", {}) or {}
            comp_inds |= {f"domain:{d}" for d in i.get("domains", []) or []}
            comp_inds |= {f"ip:{ip}" for ip in i.get("ips", []) or []}
            comp_inds |= {f"sha256:{h}" for h in i.get("sha256", []) or []}
            d = parse_email_date((batch_results[idx].get("meta", {}) or {}).get("date", ""))
            if d:
                dates.append(d)

        if not comp_inds:
            continue

        campaigns.append({
            "campaign_id": f"CAMP_{camp_num:04d}",
            "email_count": len(idxs),
            "emails": [batch_results[i].get("meta", {}).get("eml_path", "") for i in sorted(idxs)],
            "indicators": sorted(comp_inds),
            "first_seen": min(dates) if dates else None,
            "last_seen": max(dates) if dates else None,
        })
        camp_num += 1

    # Sort largest first
    campaigns.sort(key=lambda c: c["email_count"], reverse=True)
    return campaigns


# ----------------------------
# Processing
# ----------------------------

def process_single_eml(eml_path: str, config: dict) -> dict:
    msg = read_eml(eml_path)
    text = get_text_parts(msg)

    urls = extract_urls(text)
    attachments = extract_attachments(msg)

    from_raw = str(msg.get("From", ""))
    reply_raw = str(msg.get("Reply-To", ""))
    retpath_raw = str(msg.get("Return-Path", ""))

    subject_raw = str(msg.get("Subject", ""))
    date_raw = str(msg.get("Date", ""))

    from_dom = header_email_domain(from_raw)
    reply_dom = header_email_domain(reply_raw)
    ret_dom = header_email_domain(retpath_raw)

    from_reply_mismatch = bool(reply_dom and from_dom and reply_dom != from_dom)
    returnpath_mismatch = bool(ret_dom and from_dom and ret_dom != from_dom)

    auth_meta = get_auth_headers(msg)
    auth_align = auth_alignment_hints(from_dom, auth_meta)

    # URL scoring + IOC collection
    url_rows = []
    iocs_domains: Set[str] = set()
    iocs_ips: Set[str] = set()
    iocs_hashes: Set[str] = set()

    for u in urls:
        s, notes = score_url(u)
        url_rows.append({"type": "url", "value": u, "score": s, "notes": notes})
        host = domain_from_url(u)
        if host:
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
                iocs_ips.add(host)
            else:
                iocs_domains.add(host)

    for a in attachments:
        iocs_hashes.add(a["sha256"])

    brand_score, brand_notes = detect_brand_impersonation(iocs_domains, config)
    content_score, content_notes = analyze_content(text, subject_raw)

    attach_score = sum(int(a.get("risk_score", 0)) for a in attachments)
    header_score = (2 if from_reply_mismatch else 0) + (2 if returnpath_mismatch else 0)

    total_score = sum(r["score"] for r in url_rows) + brand_score + content_score + attach_score + header_score

    meta = {
        "subject": subject_raw,
        "from": from_raw,
        "reply_to": reply_raw,
        "return_path": retpath_raw,
        "date": date_raw,
        "from_domain": from_dom,
        "reply_domain": reply_dom,
        "return_path_domain": ret_dom,
        "from_reply_mismatch": from_reply_mismatch,
        "return_path_mismatch": returnpath_mismatch,
        "eml_path": eml_path,
    }

    result = {
        "metadata": {
            "tool": "phish-triage-kit",
            "version": "3.0.0",
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "meta": meta,
        "auth": auth_meta,
        "auth_alignment": auth_align,
        "urls": urls,
        "url_rows": url_rows,
        "attachments": attachments,
        "iocs": {
            "domains": sorted(iocs_domains),
            "ips": sorted(iocs_ips),
            "sha256": sorted(iocs_hashes),
            "urls": urls,
        },
        "signals": {
            "brand_score": brand_score,
            "brand_notes": brand_notes,
            "content_score": content_score,
            "content_notes": content_notes,
            "attachment_score": attach_score,
            "header_score": header_score,
        },
        "score": total_score,
    }

    # Verdict computed after enrichment (optional). For now, no intel notes.
    verdict, confidence, reasons = decide_verdict_v2(
        url_rows=url_rows,
        attachments=attachments,
        from_reply_mismatch=from_reply_mismatch,
        returnpath_mismatch=returnpath_mismatch,
        auth_meta=auth_meta,
        brand_notes=brand_notes,
        content_notes=content_notes,
        total_score=total_score,
        config=config,
        intel_notes=None,
    )
    result.update({"verdict": verdict, "confidence": confidence, "reasons": reasons})
    return result


def write_outputs_single(result: dict, outdir: str, formats: List[str]):
    os.makedirs(outdir, exist_ok=True)

    rows = []
    # URL rows as IOC rows
    for r in result.get("url_rows", []):
        rows.append({"type": "url", "value": r["value"], "score": r["score"], "notes": r["notes"]})
    # Domain/IP/Hash summary rows
    for d in result.get("iocs", {}).get("domains", []) or []:
        rows.append({"type": "domain", "value": d, "score": 0, "notes": []})
    for ip in result.get("iocs", {}).get("ips", []) or []:
        rows.append({"type": "ip", "value": ip, "score": 0, "notes": []})
    for h in result.get("iocs", {}).get("sha256", []) or []:
        rows.append({"type": "sha256", "value": h, "score": 0, "notes": []})

    if "json" in formats:
        export_json(result, os.path.join(outdir, "report.json"))
    if "csv" in formats:
        export_iocs_csv(rows, os.path.join(outdir, "iocs.csv"))
    if "markdown" in formats:
        export_markdown(result, os.path.join(outdir, "report.md"))


def list_eml_files(batch_dir: str) -> List[str]:
    p = Path(batch_dir)
    return sorted([str(x) for x in p.glob("*.eml")])


def safe_slug(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "_", name)
    return s.strip("._") or "email"


def write_outputs_per_email(result: dict, outdir: str, formats: List[str]):
    eml_path = (result.get("meta", {}) or {}).get("eml_path", "email.eml")
    stem = safe_slug(Path(eml_path).stem)
    subdir = os.path.join(outdir, stem)
    write_outputs_single(result, subdir, formats)


def run_batch(batch_dir: str, outdir: str, config: dict, parallel: bool, workers: int, logger: logging.Logger, formats: List[str]) -> Tuple[List[dict], dict]:
    emls = list_eml_files(batch_dir)
    os.makedirs(outdir, exist_ok=True)

    results: List[dict] = []
    t0 = time.time()

    if parallel and workers > 1:
        from concurrent.futures import ProcessPoolExecutor, as_completed
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(process_single_eml, f, config): f for f in emls}
            for fut in as_completed(futs):
                f = futs[fut]
                try:
                    r = fut.result()
                    results.append(r)
                    write_outputs_per_email(r, outdir, formats)
                except Exception as e:
                    logger.error(f"Failed: {f} error={e}", exc_info=True)
    else:
        for f in emls:
            try:
                r = process_single_eml(f, config)
                results.append(r)
                write_outputs_per_email(r, outdir, formats)
            except Exception as e:
                logger.error(f"Failed: {f} error={e}", exc_info=True)

    elapsed = time.time() - t0
    summary = {
        "count_total": len(emls),
        "count_ok": len(results),
        "elapsed_sec": round(elapsed, 2),
        "emails_per_sec": round((len(results) / elapsed) if elapsed > 0 else 0, 2),
        "outdir": outdir,
    }

    with open(os.path.join(outdir, "batch_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    with open(os.path.join(outdir, "batch_results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    logger.info(f"Batch complete: {summary}")
    return results, summary


# ----------------------------
# CLI
# ----------------------------

def build_arg_parser():
    ap = argparse.ArgumentParser(description="Phishing triage + IOC extraction (single or batch)")
    ap.add_argument("eml_path", nargs="?", help="Path to .eml file (single mode)")
    ap.add_argument("--batch", help="Directory containing .eml files (batch mode)")
    ap.add_argument("--outdir", default=None, help="Output directory (overrides config)")
    ap.add_argument("--config", default="config.yaml", help="Config YAML path (optional)")
    ap.add_argument("--parallel", action="store_true", help="Enable parallel processing in batch mode")
    ap.add_argument("--workers", type=int, default=None, help="Workers for parallel batch mode")
    ap.add_argument("--formats", default=None, help="Comma list: json,csv,markdown (default from config)")
    ap.add_argument("--enrich", default="", help="Comma list: urlhaus,virustotal,abuseipdb (batch only recommended)")
    ap.add_argument("--log-level", default="INFO", help="DEBUG, INFO, WARNING, ERROR")
    return ap


def main():
    args = build_arg_parser().parse_args()

    # Validate mode
    if not args.eml_path and not args.batch:
        print("error: provide an eml file path OR --batch <dir>", file=sys.stderr)
        sys.exit(2)
    if args.eml_path and args.batch:
        print("error: choose single mode (eml_path) OR batch mode (--batch), not both", file=sys.stderr)
        sys.exit(2)

    config = load_config(args.config)

    outdir = args.outdir or (config.get("general", {}) or {}).get("outdir", "outputs")
    level = getattr(logging, str(args.log_level).upper(), logging.INFO)
    logger = setup_logging(outdir, level=level)

    formats = (config.get("general", {}) or {}).get("formats", ["json", "csv", "markdown"])
    if args.formats:
        formats = [x.strip().lower() for x in args.formats.split(",") if x.strip()]
    formats = [f for f in formats if f in {"json", "csv", "markdown"}] or ["json"]

    providers = [x.strip().lower() for x in (args.enrich or "").split(",") if x.strip()]

    if args.eml_path:
        result = process_single_eml(args.eml_path, config)

        # Optional enrichment for single file (URLs + hashes + IPs)
        if providers:
            # wrap in list to reuse batch enrichment and notes
            enriched_results, intel_notes = enrich_batch([result], outdir, config, providers, logger)
            result = enriched_results[0]
            # recompute verdict with intel category
            verdict, confidence, reasons = decide_verdict_v2(
                url_rows=result.get("url_rows", []),
                attachments=result.get("attachments", []),
                from_reply_mismatch=(result.get("meta", {}) or {}).get("from_reply_mismatch", False),
                returnpath_mismatch=(result.get("meta", {}) or {}).get("return_path_mismatch", False),
                auth_meta=result.get("auth", {}) or {},
                brand_notes=(result.get("signals", {}) or {}).get("brand_notes", []) or [],
                content_notes=(result.get("signals", {}) or {}).get("content_notes", []) or [],
                total_score=int(result.get("score", 0)),
                config=config,
                intel_notes=intel_notes,
            )
            result.update({"verdict": verdict, "confidence": confidence, "reasons": reasons})

        write_outputs_single(result, outdir, formats)
        print(f"[+] Wrote outputs to {outdir}")
        return

    # Batch mode
    parallel = bool(args.parallel) or bool((config.get("general", {}) or {}).get("parallel", True))
    workers = args.workers or int((config.get("general", {}) or {}).get("workers", 4))

    results, summary = run_batch(args.batch, outdir, config, parallel, workers, logger, formats)

    # Campaign correlation
    campaigns = build_campaigns(results)
    with open(os.path.join(outdir, "batch_campaigns.json"), "w", encoding="utf-8") as f:
        json.dump(campaigns, f, indent=2)

    # Optional enrichment AFTER batch (sequential + cached)
    intel_notes: List[str] = []
    if providers:
        try:
            results, intel_notes = enrich_batch(results, outdir, config, providers, logger)
            with open(os.path.join(outdir, "batch_results_enriched.json"), "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
        except Exception as e:
            logger.error(f"Enrichment failed: {e}", exc_info=True)

    print(f"[+] Batch outputs in {outdir}")
    print(f"[+] Summary: {os.path.join(outdir, 'batch_summary.json')}")
    print(f"[+] Campaigns: {os.path.join(outdir, 'batch_campaigns.json')}")


if __name__ == "__main__":
    main()
