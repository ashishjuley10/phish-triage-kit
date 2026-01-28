#!/usr/bin/env python3
import argparse
import csv
import hashlib
import os
import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

# URL patterns (plain text + common obfuscations)
URL_REGEX = re.compile(r'(?i)\b((?:https?://|hxxps?://|www\.)[^\s<>"\']+)')
HREF_REGEX = re.compile(r'(?i)href\s*=\s*["\']([^"\']+)["\']')

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly"
}

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "kim", "work", "country"}

EMAILISH_RE = re.compile(
    r'([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|@[A-Za-z0-9.-]+\.[A-Za-z]{2,})'
)

def sanitize_md(s: str) -> str:
    """
    Prevent Glow/markdown renderers from linkifying emails/@domains and showing mailto:...
    - removes literal 'mailto:'
    - wraps emails and @domains in backticks
    """
    s = (s or "").replace("mailto:", "")
    return EMAILISH_RE.sub(r'`\1`', s)

def shorten_one_line(s: str, n: int = 240) -> str:
    s = (s or "").replace("\n", " ").replace("\r", " ")
    return s if len(s) <= n else s[:n] + "…"

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def read_eml(path: str):
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg

def get_text_parts(msg) -> str:
    texts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", "")).lower()
            if ctype in ("text/plain", "text/html") and "attachment" not in disp:
                try:
                    texts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            texts.append(msg.get_content())
        except Exception:
            pass
    return "\n".join([t for t in texts if t])

def deobfuscate(s: str) -> str:
    s = s.replace("hxxp://", "http://").replace("hxxps://", "https://")
    s = s.replace("[.]", ".").replace("(.)", ".")
    return s

def normalise_url(u: str) -> str:
    u = u.strip().strip(").,;:]>\"'")
    if u.lower().startswith("www."):
        u = "http://" + u
    return u

def extract_urls(text: str):
    text = deobfuscate(text)
    urls = set()

    # 1) plain text URLs
    for m in URL_REGEX.findall(text):
        urls.add(normalise_url(m))

    # 2) href links from HTML emails
    for m in HREF_REGEX.findall(text):
        urls.add(normalise_url(deobfuscate(m)))

    cleaned = []
    for u in urls:
        if u.lower().startswith(("http://", "https://")):
            cleaned.append(u)
    return sorted(set(cleaned))

def domain_from_url(u: str) -> str:
    try:
        p = urlparse(u)
        host = p.netloc.split("@")[-1]
        host = host.split(":")[0].strip().lower()
        return host
    except Exception:
        return ""

def score_url(u: str):
    score = 0
    notes = []
    host = domain_from_url(u)

    if not host:
        return 0, "no_host"

    if "xn--" in host:
        score += 3
        notes.append("punycode")

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        score += 4
        notes.append("ip_host")

    if host in SHORTENERS:
        score += 3
        notes.append("shortener")

    parts = host.split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        if tld in SUSPICIOUS_TLDS:
            score += 2
            notes.append(f"tld:{tld}")

    if u.lower().startswith("http://"):
        score += 1
        notes.append("http_not_https")

    return score, ",".join(notes) if notes else "ok"

def extract_attachments(msg):
    atts = []
    for part in msg.walk():
        disp = str(part.get("Content-Disposition", "")).lower()
        if "attachment" in disp:
            filename = part.get_filename() or "unknown"
            payload = part.get_payload(decode=True) or b""
            atts.append({
                "filename": filename,
                "sha256": sha256_bytes(payload),
                "size_bytes": len(payload),
                "content_type": part.get_content_type(),
            })
    return atts

def header_domain(addr: str) -> str:
    if not addr:
        return ""
    m = re.search(r'@([A-Za-z0-9\.-]+\.[A-Za-z]{2,})', addr)
    return m.group(1).lower() if m else ""

def get_auth_headers(msg) -> dict:
    """Capture common auth-related headers if present (sanitised for markdown)."""
    keys = ["Authentication-Results", "Received-SPF", "ARC-Authentication-Results"]
    out = {}
    for k in keys:
        v = msg.get(k)
        if v:
            vv = shorten_one_line(str(v))
            out[k] = sanitize_md(vv)
        else:
            out[k] = "(missing)"
    return out

def auth_pass_summary(auth_meta: dict) -> dict:
    blob = " ".join(str(v).lower() for v in auth_meta.values() if v)
    return {
        "spf_pass": "spf=pass" in blob or "received-spf: pass" in blob,
        "dkim_pass": "dkim=pass" in blob,
        "dmarc_pass": "dmarc=pass" in blob,
    }

def decide_verdict(url_rows, attachments, mismatch: bool, auth_meta: dict):
    high_risk = any(r["score"] >= 4 for r in url_rows)
    has_shortener = any("shortener" in r["notes"] for r in url_rows)
    has_attachment = len(attachments) > 0

    auth = auth_pass_summary(auth_meta)
    all_auth_pass = auth["spf_pass"] and auth["dkim_pass"] and auth["dmarc_pass"]

    if high_risk or has_attachment:
        verdict = "Suspicious"
        confidence = "High" if high_risk else "Medium"
    elif mismatch:
        verdict = "Suspicious"
        confidence = "Medium"
    elif has_shortener:
        verdict = "Needs Review"
        confidence = "Medium"
    else:
        verdict = "Needs Review"
        confidence = "Low"

    reasons = []
    if high_risk: reasons.append("High-risk URL indicator(s)")
    if has_shortener: reasons.append("URL shortener present")
    if mismatch: reasons.append("From/Reply-To domain mismatch")
    if has_attachment: reasons.append("Attachment present")

    if all_auth_pass:
        reasons.append("SPF/DKIM/DMARC pass (reduces likelihood of spoofing)")
        if not high_risk and not has_attachment and confidence == "Medium":
            confidence = "Low"

    if not reasons:
        reasons.append("Insufficient indicators in sample")

    return verdict, confidence, reasons

def build_report(meta, auth_meta, urls, url_rows, attachments, verdict_tuple):
    verdict, confidence, reasons = verdict_tuple

    lines = []
    lines.append("# Phishing Triage Report")
    lines.append("")

    lines.append("## Verdict")
    lines.append(f"- **Verdict**: {verdict}")
    lines.append(f"- **Confidence**: {confidence}")
    lines.append(f"- **Reasons**: {', '.join(reasons)}")
    lines.append("")

    lines.append("## Message Metadata")
    for k, v in meta.items():
        lines.append(f"- **{k}**: {v}")
    lines.append("")

    lines.append("## Authentication Signals (if present)")
    for k, v in auth_meta.items():
        lines.append(f"- **{k}**: {v}")
    lines.append("")

    lines.append("## Summary")
    lines.append(f"- URLs found: **{len(urls)}**")
    lines.append(f"- Attachments found: **{len(attachments)}**")
    hi = [r for r in url_rows if r["score"] >= 4]
    lines.append(f"- High-risk URLs (score ≥ 4): **{len(hi)}**")
    lines.append("")

    lines.append("## Top URLs (by score)")
    for r in sorted(url_rows, key=lambda x: x["score"], reverse=True)[:10]:
        lines.append(f"- **{r['score']}** — {r['value']} ({r['notes']})")
    lines.append("")

    lines.append("## Attachments")
    if attachments:
        for a in attachments:
            lines.append(
                f"- {a['filename']} — {a['content_type']} — sha256: `{a['sha256']}` — {a['size_bytes']} bytes"
            )
    else:
        lines.append("- None detected")
    lines.append("")

    lines.append("## Analyst Next Steps (recommended)")
    lines.append("- Validate sender authenticity (SPF/DKIM/DMARC results if available in headers).")
    lines.append("- Detonate URLs/attachments only in a safe sandbox; enrich IOCs with reputation checks.")
    lines.append("- Document verdict with evidence and confidence level.")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(description="Minimal phishing triage + IOC extractor")
    ap.add_argument("eml_path", help="Path to .eml file")
    ap.add_argument("--outdir", default="outputs", help="Output directory")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    msg = read_eml(args.eml_path)
    text = get_text_parts(msg)

    urls = extract_urls(text)
    attachments = extract_attachments(msg)

    from_h_raw = str(msg.get("From", ""))
    reply_to_raw = str(msg.get("Reply-To", ""))
    subject_raw = str(msg.get("Subject", ""))
    date_raw = str(msg.get("Date", ""))

    from_dom = header_domain(from_h_raw)
    reply_dom = header_domain(reply_to_raw)
    mismatch = bool(reply_dom and from_dom and reply_dom != from_dom)

    # sanitize for markdown rendering
    from_h = sanitize_md(from_h_raw)
    reply_to = sanitize_md(reply_to_raw) if reply_to_raw else "(none)"
    subject = sanitize_md(subject_raw)
    date = sanitize_md(date_raw) if date_raw else "(unknown)"

    meta = {
        "Subject": subject,
        "From": from_h,
        "Reply-To": reply_to,
        "Date": date,
        "From domain": from_dom if from_dom else "(unknown)",
        "Reply-To domain": reply_dom if reply_dom else "(none)",
        "From/Reply-To mismatch": "YES" if mismatch else "no",
    }

    auth_meta = get_auth_headers(msg)

    rows = []
    url_rows = []
    for u in urls:
        score, notes = score_url(u)
        url_row = {"type": "url", "value": u, "score": score, "notes": notes}
        url_rows.append(url_row)
        rows.append(url_row)

        host = domain_from_url(u)
        if host:
            rows.append({"type": "domain", "value": host, "score": score, "notes": "from_url"})

    for a in attachments:
        rows.append({"type": "file_sha256", "value": a["sha256"], "score": 5, "notes": a["filename"]})

    verdict_tuple = decide_verdict(url_rows, attachments, mismatch, auth_meta)

    csv_path = os.path.join(args.outdir, "iocs.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["type", "value", "score", "notes"])
        w.writeheader()
        for r in rows:
            w.writerow(r)

    report_path = os.path.join(args.outdir, "report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(build_report(meta, auth_meta, urls, url_rows, attachments, verdict_tuple))

    print(f"[+] Wrote {csv_path}")
    print(f"[+] Wrote {report_path}")

if __name__ == "__main__":
    main()
