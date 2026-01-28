# Phish Triage Kit 🛡️
A lightweight phishing triage tool that parses `.eml` emails, extracts IOCs, surfaces email authentication signals (SPF/DKIM/DMARC), and produces an analyst-style verdict report + IOC exports for enrichment/blocking workflows.

> Built to demonstrate junior SOC / Threat Research capability: evidence-led analysis, repeatable triage, and clean outputs.

---

## Why this exists
Most “phishing projects” stop at *finding URLs*. In real triage you need:
- **Evidence** (what indicators exist and why they matter)
- **Context** (auth signals that reduce/raise spoofing likelihood)
- **Outputs that feed operations** (CSV IOCs, report for ticketing)

This tool converts raw email artifacts into **actionable triage output**.

---

## What it does (Features)
✅ Parses `.eml` including multipart emails (text + HTML)  
✅ Extracts URLs from:
- plain text
- HTML `href` attributes  
✅ Deobfuscates common patterns (e.g., `hxxp`, `[.]`)  
✅ Scores URL indicators (explainable):
- URL shorteners
- IP-host URLs
- HTTP (not HTTPS)
- suspicious TLDs
- punycode domains  
✅ Extracts attachments (if present) and calculates **SHA-256**  
✅ Surfaces authentication context (if present in headers):
- `Authentication-Results`
- `Received-SPF`
- `ARC-Authentication-Results`  
✅ Generates two outputs:
- `outputs/iocs.csv` — IOCs for enrichment/blocking
- `outputs/report.md` — analyst report (verdict + confidence + evidence + next steps)

---

## Outputs (What you get)
### 1) Analyst Report (`outputs/report.md`)
Includes:
- **Verdict**: `Suspicious` / `Needs Review`
- **Confidence**: `High` / `Medium` / `Low`
- **Reasons**: evidence-based indicators
- **Message metadata**: From, Reply-To, domain checks
- **Auth signals**: SPF/DKIM/DMARC context (if present)
- **Top URLs ranked by score**
- **Attachments section** (hashes + metadata)
- **Recommended next steps**

### 2) IOC Export (`outputs/iocs.csv`)
Columns:
- `type` (url / domain / file_sha256)
- `value`
- `score`
- `notes`

---

## Quickstart (60 seconds)
### Prerequisites
- Python 3.10+ recommended

### Run
```bash
python3 phish_triage.py samples/sample1.eml --outdir outputs
python3 phish_triage.py samples/sample2.eml --outdir outputs
