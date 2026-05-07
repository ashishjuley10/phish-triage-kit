# Phish Triage Kit

Python-based phishing email triage tool for parsing `.eml` files, extracting indicators of compromise (IOCs), scoring suspicious signals, and producing analyst-friendly outputs for single-email or batch review.

This project demonstrates practical junior threat research skills: phishing email analysis, malicious URL triage, IOC extraction, repeatable reporting, campaign-style grouping, and Python automation for high-volume security artifacts.

## What it does

- Analyses single `.eml` files
- Analyses folders of `.eml` files in batch mode
- Extracts URLs, domains, IP addresses, and attachment hashes
- Defangs suspicious indicators for safe reporting
- Reviews basic header/authentication fields where available
- Scores phishing signals using rule-based logic
- Produces JSON, CSV, and Markdown reports
- Groups related emails into campaign-style clusters using shared indicators
- Supports optional enrichment using URLhaus, VirusTotal, and AbuseIPDB
- Supports parallel batch processing with configurable workers

## Why I built it

Phishing emails often contain repeated indicators such as suspicious domains, IP-hosted URLs, URL shorteners, impersonation patterns, and credential-request language.

Manually checking these across many emails is slow and inconsistent. This tool automates first-pass triage so an analyst can quickly see:

- what indicators were found
- why the email looks suspicious
- what the risk score is
- whether emails share campaign indicators
- what outputs can be passed into another workflow

The tool is not designed to replace a human analyst. It is designed to reduce repetitive work and give analysts a structured starting point.

## Installation

```bash
git clone https://github.com/ashishjuley10/phish-triage-kit.git
cd phish-triage-kit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Check the CLI:

```bash
python3 phish_triage.py --help
```

## Usage

Analyse one email:

```bash
python3 phish_triage.py samples/sample1.eml --outdir outputs/sample1 --formats json,csv,markdown
```

Analyse a batch of emails:

```bash
python3 phish_triage.py --batch samples --outdir outputs/batch --formats json,csv,markdown
```

Analyse a batch using parallel processing:

```bash
python3 phish_triage.py --batch samples --outdir outputs/batch_parallel --parallel --workers 4 --formats json,csv,markdown
```

Run optional threat-intelligence enrichment:

```bash
python3 phish_triage.py --batch samples --outdir outputs/enriched --enrich urlhaus,virustotal,abuseipdb --formats json,csv,markdown
```

## CLI options

```text
python3 phish_triage.py [eml_path] [options]

eml_path              Path to .eml file for single-email mode

--batch BATCH         Directory containing .eml files for batch mode
--outdir OUTDIR       Output directory
--config CONFIG       Path to config file, default: config.yaml
--parallel            Enable parallel processing in batch mode
--workers WORKERS     Number of workers for parallel batch mode
--formats FORMATS     Comma list: json,csv,markdown
--enrich ENRICH       Comma list: urlhaus,virustotal,abuseipdb
--log-level LEVEL     DEBUG, INFO, WARNING, or ERROR
```

## Example output

Example verdict from a phishing-style sample:

```text
Verdict: Phish
Confidence: High
Risk Score: 17

Reasons:
- IP-hosted URL
- Non-HTTPS link
- Suspicious phishing keywords
- Credential-request language
```

Example extracted IOCs:

| Type | Value |
|---|---|
| URL | `http://185.92.10.10/update` |
| URL | `https://bit.ly/abc123` |
| URL | `https://paypai-secure.com/login` |
| Domain | `paypai-secure.com` |
| Domain | `bit.ly` |
| IP | `185.92.10.10` |

## Batch and campaign output

In batch mode, the tool can produce:

```text
batch_results.json
batch_summary.json
batch_campaigns.json
```

`batch_campaigns.json` groups related emails using shared indicators such as domains, IP addresses, URLs, or attachment hashes.

This helps move from single-email triage to campaign-style review.

## Benchmark snapshot

A benchmark run on a 120-email corpus produced:

| Test | Result |
|---|---:|
| Emails processed | 120/120 |
| Parsing failures | 0 |
| Single-worker throughput | 576 emails/sec |
| Best parallel throughput | 1,153 emails/sec |
| Best worker setting | 4 workers |

These results are hardware and corpus dependent.

## Sample phishing analysis report

### Overview

This is a sample analyst-style report produced from a suspicious phishing-style `.eml` file.

The purpose of this report is to show how the Phish Triage Kit supports first-pass phishing triage by extracting indicators, identifying suspicious patterns, and producing a structured summary for further review.

### Verdict

**Verdict:** Phish  
**Confidence:** High  
**Risk score:** 17

### Email summary

| Field | Value |
|---|---|
| Subject | Account Update Required |
| Sender | support@paypai-secure.com |
| Reply-To | support@paypai-secure.com |
| Recipient | user@example.com |
| Attachment | None observed in sample |

### Key findings

The email was assessed as high-risk due to multiple phishing indicators:

- The message uses account-security urgency to pressure the recipient.
- The email contains credential-request language.
- The email includes a suspicious lookalike domain.
- One URL uses HTTP rather than HTTPS.
- One URL is hosted directly on an IP address.
- A URL shortener is present, which may hide the final destination.
- The domain appears designed to impersonate a known brand.

### Extracted indicators

| Type | Indicator | Notes |
|---|---|---|
| URL | `http://185.92.10.10/update` | IP-hosted URL and non-HTTPS |
| URL | `https://bit.ly/abc123` | URL shortener |
| URL | `https://paypai-secure.com/login` | Lookalike phishing-style domain |
| Domain | `paypai-secure.com` | Possible brand impersonation |
| Domain | `bit.ly` | URL shortening service |
| IP | `185.92.10.10` | Direct IP-hosted URL |

### Analyst reasoning

The strongest signal is the use of a lookalike domain: `paypai-secure.com`.

This resembles a brand-impersonation pattern where attackers register a domain that looks visually similar to a legitimate service. The goal is usually to make the recipient believe they are logging into a trusted platform.

The IP-hosted URL is also suspicious because legitimate customer-facing login portals normally use branded domains with valid HTTPS. The non-HTTPS link increases risk because credentials or session data could be exposed or intercepted.

The URL shortener adds another risk because it hides the final destination from the user and makes quick manual inspection harder.

### Recommended analyst action

Recommended next steps:

1. Do not click the links directly on a host machine.
2. Investigate URLs in a safe sandbox or isolated VM.
3. Check domain age, DNS records, hosting provider, and reputation.
4. Search for shared indicators across other emails.
5. Block confirmed malicious domains, IPs, and URLs where appropriate.
6. Preserve the original `.eml` file for evidence and further investigation.

## Security notes

This tool is for defensive security learning, phishing triage, and authorised research only.

When analysing suspicious emails:

- Use a VM or isolated environment
- Do not open or execute attachments
- Do not browse suspicious links directly from your host machine
- Treat email content as potentially sensitive
- Be careful when enabling external enrichment because IOCs may be sent to third-party services

## Limitations

- This is a triage tool, not a malware sandbox
- It does not perform dynamic malware analysis
- It does not currently support `.msg`, `.pst`, or live mailbox ingestion
- API enrichment depends on provider availability, API keys, and rate limits
- Scoring is rule-based and should be reviewed by a human analyst before action is taken

## Skills demonstrated

- Python security automation
- Email and MIME parsing
- IOC extraction and defanging
- Phishing and malicious URL triage
- Rule-based scoring
- Batch processing
- Multiprocessing
- JSON, CSV, and Markdown reporting
- Campaign correlation concepts
- Threat-intelligence enrichment design
- Defensive security documentation

## Author

Ashish Juley  
BSc (Hons) Cyber Security & Digital Forensics  
GitHub: github.com/ashishjuley10
