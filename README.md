# Phish Triage Kit (SOC-Style) : Email Triage, IOC Extraction, Enrichment, and Campaign Correlation

Phish Triage Kit is a Linux-friendly phishing triage tool that converts `.eml` emails into SOC-ready outputs: extracted indicators (URLs/domains/IPs/hashes), risk scoring and verdicting, optional threat-intelligence enrichment (URLhaus/VirusTotal/AbuseIPDB), and campaign correlation across large batches of emails.

This project is designed to demonstrate practical Threat Research / SOC automation skills: triaging high volumes of phishing artifacts, enriching IOCs with industry sources, and clustering related emails into campaigns.

---

## What this tool does

Given a single `.eml` file or a directory of `.eml` files, the tool:

1. Parses emails (including multipart emails and HTML content).
2. Extracts and deobfuscates IOCs, especially URLs (e.g., `hxxp` → `http`, `evil[.]com` → `evil.com`).
3. Scores risk signals (URL properties, header mismatches, brand impersonation, and social-engineering language).
4. Produces a verdict (`Phish`, `Suspicious`, `Needs Review`) with concise reasons.
5. Optionally enriches IOCs using threat-intelligence providers with caching and rate limiting.
6. In batch mode, correlates emails into campaigns based on shared indicators.

---

## Features

### Email parsing
- Supports `.eml` parsing with the Python email library.
- Extracts content from:
  - `text/plain`
  - `text/html` (with a safe/limited HTML-to-text conversion)

### IOC extraction
- URL extraction from:
  - visible text
  - HTML `href=...` attributes
- URL deobfuscation of common patterns:
  - `hxxp://` / `hxxps://` → `http://` / `https://`
  - `[.]` / `(.)` / `{.}` → `.`
  - some whitespace/dot obfuscation patterns
- IOC inventory:
  - URLs
  - Domains (from URL hosts)
  - IPs (from IP-hosted URLs)
  - Attachment SHA-256 hashes

### Risk scoring and verdicting
- URL scoring heuristics:
  - IP-hosted URLs
  - URL shorteners
  - punycode / IDN indicators
  - suspicious TLDs
  - phishing keyword patterns in paths (login/verify/update/secure/etc.)
  - non-HTTPS usage
  - long/complex URLs and excessive subdomains
- Brand impersonation detection:
  - brand keyword presence in domains (e.g., `paypal-verify...`)
  - typosquatting detection using Levenshtein distance on base domains
  - punycode presence indicators
- Social-engineering language heuristics:
  - urgency language
  - credential requests
  - threat/consequence language
  - generic greetings (low personalization)
- Header mismatch signals:
  - From vs Reply-To domain mismatch
  - From vs Return-Path domain mismatch
- Verdict logic:
  - `Phish`, `Suspicious`, or `Needs Review`
  - configurable thresholds
  - optional rule requiring at least two indicator categories for `Phish`

### Batch mode and scale
- Batch processing of a directory containing `.eml` files.
- Optional parallel execution with configurable worker count.
- Batch summary metrics:
  - processed count
  - elapsed time
  - throughput (emails/sec)
- Campaign correlation:
  - clusters emails by shared domains, IPs, and attachment hashes

### Threat-intelligence enrichment (optional)
- URLhaus (no API key required)
- VirusTotal (API key via environment variable)
- AbuseIPDB (API key via environment variable)
- Caching to reduce repeated queries across runs
- Rate limiting for providers with request-per-minute constraints

### Outputs
Per email:
- `report.json` (structured, tool-friendly output)
- `report.md` (human-readable summary)
- `iocs.csv` (simple tabular IOC export)

Batch:
- `batch_summary.json`
- `batch_results.json`
- `batch_campaigns.json`
- `batch_enrichment.json` (when enrichment enabled)
- `batch_results_enriched.json` (when enrichment enabled)

---

## Requirements

- Python 3.10+ recommended (works well on Linux)
- Dependencies are listed in `requirements.txt`

Install dependencies:
```bash
pip install -r requirements.txt
