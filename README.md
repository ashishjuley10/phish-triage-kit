# Phish Triage Kit (SOC-Style): Email Triage, IOC Extraction, Enrichment, and Campaign Correlation

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/ashishjuley10/phish-triage-kit/graphs/commit-activity)

A comprehensive Linux-friendly phishing triage tool that converts `.eml` emails into SOC-ready outputs: extracted indicators (URLs/domains/IPs/hashes), risk scoring and verdicting, optional threat-intelligence enrichment (URLhaus/VirusTotal/AbuseIPDB), and campaign correlation across large batches of emails.

This project is designed to demonstrate practical **Threat Research / SOC automation skills**: triaging high volumes of phishing artifacts, enriching IOCs with industry sources, and clustering related emails into campaigns.

---

## 🎯 Key Features

- **📧 Email Parsing**: Extracts metadata, headers, body content, and attachments from `.eml` files
- **🔍 IOC Extraction**: Automatically identifies and extracts URLs, domains, IP addresses, email addresses, and file hashes
- **🛡️ SPF/DKIM/DMARC Analysis**: Surfaces authentication signals to assess email legitimacy
- **⚖️ Risk Scoring & Verdicting**: Generates analyst-style verdicts (Malicious/Suspicious/Clean) with confidence scores
- **🌐 Threat Intelligence Enrichment**: Optional integration with URLhaus, VirusTotal, and AbuseIPDB for IOC reputation checks
- **📊 Campaign Correlation**: Clusters related phishing emails based on shared IOCs and patterns
- **🔄 Batch Processing**: Analyze multiple emails simultaneously for efficient SOC workflows
- **📄 Multiple Output Formats**: Generate reports in text, JSON, or HTML formats
- **🎨 SOC-Ready Reports**: Professional, structured output suitable for incident response documentation

---

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Configuration](#configuration)
- [Features in Detail](#features-in-detail)
- [Output Examples](#output-examples)
- [API Keys Setup](#api-keys-setup)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## 🚀 Installation

### Prerequisites

- **Python 3.7+**
- **pip** (Python package manager)
- **Linux/macOS** (recommended) or Windows with WSL
- Internet connection (for threat intelligence enrichment)

### Step 1: Clone the Repository

```bash
git clone https://github.com/ashishjuley10/phish-triage-kit.git
cd phish-triage-kit
```

### Step 2: Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# Linux/macOS:
source venv/bin/activate

# Windows:
venv\\Scripts\\activate
```

### Step 3: Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Verify Installation

```bash
python phish_triage.py --help
```

If you see the help menu, installation was successful! ✅

---

## ⚡ Quick Start

### Analyze a Single Email

```bash
python phish_triage.py -f samples/phishing_email.eml
```

### Batch Analysis with Enrichment

```bash
python phish_triage.py -d samples/ --enrich --output reports/
```

### Generate JSON Report

```bash
python phish_triage.py -f email.eml --format json -o report.json
```

---

## 📖 Usage

### Command-Line Options

```bash
python phish_triage.py [OPTIONS]

Required (one of):
  -f, --file FILE              Path to single .eml file
  -d, --directory DIR          Path to directory containing .eml files

Optional:
  -o, --output PATH            Output directory for reports (default: ./reports/)
  --format FORMAT              Output format: text|json|html (default: text)
  --enrich                     Enable threat intelligence enrichment
  --campaign                   Enable campaign correlation analysis
  --extract-attachments        Extract email attachments to disk
  --no-verdict                 Skip automatic verdict generation
  -v, --verbose                Enable verbose logging
  -h, --help                   Show help message
```

### Usage Examples

**1. Basic Email Analysis**
```bash
python phish_triage.py -f suspicious_email.eml
```

**2. Batch Processing with Enrichment**
```bash
python phish_triage.py -d ./emails/ --enrich --format json
```

**3. Full SOC Analysis (Enrichment + Campaign Correlation)**
```bash
python phish_triage.py -d ./inbox/ --enrich --campaign -o ./triage_reports/
```

**4. Extract Attachments for Further Analysis**
```bash
python phish_triage.py -f email.eml --extract-attachments -o ./extracted/
```

**5. Verbose Mode for Debugging**
```bash
python phish_triage.py -f email.eml -v
```

---

## ⚙️ Configuration

### config.yaml Overview

The `config.yaml` file controls tool behavior and API integrations:

```yaml
# Threat Intelligence APIs
threat_intel:
  urlhaus:
    enabled: true
    api_url: "https://urlhaus-api.abuse.ch/v1/"
  
  virustotal:
    enabled: true
    api_key: "YOUR_VT_API_KEY_HERE"
  
  abuseipdb:
    enabled: true
    api_key: "YOUR_ABUSEIPDB_KEY_HERE"

# Verdict Thresholds
scoring:
  malicious_threshold: 70    # Score >= 70 = Malicious
  suspicious_threshold: 40   # Score >= 40 = Suspicious
  
# Campaign Correlation
campaign:
  min_common_iocs: 3        # Minimum shared IOCs to link emails
  similarity_threshold: 0.7  # Subject/body similarity threshold
```

### Environment Variables (Alternative)

For better security, use environment variables instead of hardcoding API keys:

```bash
export VIRUSTOTAL_API_KEY="your_api_key_here"
export ABUSEIPDB_API_KEY="your_api_key_here"
```

---

## 🔬 Features in Detail

### 1. Email Metadata Extraction

Extracts comprehensive email metadata:
- **Headers**: From, To, Subject, Date, Message-ID, Reply-To
- **Routing**: Received headers, originating IP addresses
- **Authentication**: SPF, DKIM, DMARC results
- **Attachments**: Filenames, MIME types, sizes, hashes

### 2. IOC Extraction

Automatically identifies and extracts:
- **URLs**: Full URL extraction with defanging support
- **Domains**: Parent domains and subdomains
- **IP Addresses**: IPv4 and IPv6 addresses
- **Email Addresses**: Sender, reply-to, and embedded addresses
- **File Hashes**: MD5, SHA1, SHA256 of attachments

### 3. Threat Intelligence Enrichment

Enriches IOCs using multiple sources:

**URLhaus**
- URL reputation and threat classification
- Associated malware families
- First seen/last seen timestamps

**VirusTotal**
- URL/domain/IP/file hash reputation
- Detection ratios from multiple engines
- Community votes and comments

**AbuseIPDB**
- IP address abuse reports
- Confidence scores
- Geolocation data

### 4. Risk Scoring & Verdicting

Automated risk assessment based on:
- Authentication failures (SPF/DKIM/DMARC)
- Known malicious IOCs from threat intel
- Suspicious patterns (URL shorteners, file extensions)
- Domain age and reputation
- Attachment types

**Verdict Categories**:
- 🔴 **Malicious** (Score: 70-100): Clear indicators of phishing/malware
- 🟡 **Suspicious** (Score: 40-69): Multiple red flags, needs investigation
- 🟢 **Clean** (Score: 0-39): Likely legitimate email

### 5. Campaign Correlation

Links related phishing emails by analyzing:
- Shared IOCs (URLs, domains, IPs, hashes)
- Subject line similarity
- Sender patterns
- Temporal proximity
- Body content similarity

**Output**: Campaign clusters with shared characteristics and timeline

### 6. Batch Processing

Efficiently process large volumes of emails:
- Parallel processing support
- Progress tracking
- Aggregate statistics
- Campaign-wide reporting

---

## 📊 Output Examples

### Text Report (Analyst-Ready)

```
╔══════════════════════════════════════════════════════════════╗
║              PHISHING TRIAGE REPORT                          ║
╚══════════════════════════════════════════════════════════════╝

Analysis Timestamp: 2026-01-30 15:42:11 UTC
Email File: suspicious_email.eml

┌─────────────────────────────────────────────────────────────┐
│ EMAIL METADATA                                               │
└─────────────────────────────────────────────────────────────┘
From:           security@paypa1-verify.com
To:             victim@company.com
Subject:        Urgent: Account Verification Required
Date:           2026-01-29 14:23:11 UTC
Message-ID:     <abc123@malicious-server.com>

┌─────────────────────────────────────────────────────────────┐
│ AUTHENTICATION ANALYSIS                                      │
└─────────────────────────────────────────────────────────────┘
SPF:            ❌ FAIL (IP not authorized)
DKIM:           ❌ NONE (No signature present)
DMARC:          ❌ FAIL (Policy: reject)

Originating IP: 185.220.101.45
Geolocation:    Russia, Moscow

┌─────────────────────────────────────────────────────────────┐
│ EXTRACTED IOCs                                               │
└─────────────────────────────────────────────────────────────┘

URLs (3):
  [1] http://paypa1-verify[.]com/secure/login
      ├─ URLhaus: MALICIOUS (Phishing)
      └─ VirusTotal: 42/89 engines flagged

  [2] http://bit[.]ly/3xYz123
      ├─ Redirect to: http://credential-harvester[.]net
      └─ URL Shortener detected

  [3] http://malicious-cdn[.]ru/invoice.pdf.exe
      └─ Suspicious file extension: .pdf.exe

Domains (2):
  [1] paypa1-verify[.]com (Typosquatting: paypal.com)
      ├─ Created: 2 days ago
      └─ Registrar: NameCheap (commonly abused)

  [2] credential-harvester[.]net
      └─ VirusTotal: 38/89 engines flagged

IP Addresses (1):
  [1] 185.220.101[.]45
      ├─ AbuseIPDB: 95% confidence (78 reports)
      └─ Country: Russia

┌─────────────────────────────────────────────────────────────┐
│ ATTACHMENTS                                                  │
└─────────────────────────────────────────────────────────────┘
[1] invoice.pdf.exe
    ├─ Size: 2.4 MB
    ├─ MD5: 5d41402abc4b2a76b9719d911017c592
    ├─ SHA256: 2c26b46b68ffc68ff99b453c1d30413413...
    └─ VirusTotal: 54/72 engines detected as malware

┌─────────────────────────────────────────────────────────────┐
│ RISK ASSESSMENT                                              │
└─────────────────────────────────────────────────────────────┘
Overall Risk Score: 92/100

Verdict: 🔴 MALICIOUS
Confidence: 95%

Risk Factors:
  ✗ All email authentication checks failed
  ✗ Multiple known malicious IOCs
  ✗ Domain typosquatting detected
  ✗ Malicious attachment confirmed
  ✗ Sender from high-risk country
  ✗ Recently registered domain

┌─────────────────────────────────────────────────────────────┐
│ ANALYST RECOMMENDATIONS                                      │
└─────────────────────────────────────────────────────────────┘
1. QUARANTINE this email immediately
2. Block sender domain: paypa1-verify[.]com
3. Add IOCs to threat intelligence feeds
4. Check for similar emails in environment
5. Notify end user of phishing attempt
6. Report to abuse contacts and registrar

╔══════════════════════════════════════════════════════════════╗
║                   END OF REPORT                              ║
╚══════════════════════════════════════════════════════════════╝
```

### JSON Report (SIEM Integration)

```json
{
  "analysis_metadata": {
    "timestamp": "2026-01-30T15:42:11Z",
    "tool_version": "1.0.0",
    "email_file": "suspicious_email.eml"
  },
  "email_metadata": {
    "from": "security@paypa1-verify.com",
    "to": "victim@company.com",
    "subject": "Urgent: Account Verification Required",
    "date": "2026-01-29T14:23:11Z",
    "message_id": "<abc123@malicious-server.com>"
  },
  "authentication": {
    "spf": {
      "result": "FAIL",
      "details": "IP not authorized"
    },
    "dkim": {
      "result": "NONE",
      "details": "No signature present"
    },
    "dmarc": {
      "result": "FAIL",
      "policy": "reject"
    }
  },
  "iocs": {
    "urls": [
      {
        "url": "http://paypa1-verify.com/secure/login",
        "defanged": "http://paypa1-verify[.]com/secure/login",
        "enrichment": {
          "urlhaus": {
            "status": "malicious",
            "category": "phishing"
          },
          "virustotal": {
            "detections": 42,
            "total_engines": 89,
            "detection_rate": 0.47
          }
        }
      }
    ],
    "domains": [
      {
        "domain": "paypa1-verify.com",
        "typosquatting": {
          "detected": true,
          "target": "paypal.com"
        },
        "age_days": 2,
        "registrar": "NameCheap"
      }
    ],
    "ips": [
      {
        "ip": "185.220.101.45",
        "geolocation": {
          "country": "Russia",
          "city": "Moscow"
        },
        "abuseipdb": {
          "confidence_score": 95,
          "total_reports": 78
        }
      }
    ]
  },
  "attachments": [
    {
      "filename": "invoice.pdf.exe",
      "size_bytes": 2516582,
      "md5": "5d41402abc4b2a76b9719d911017c592",
      "sha256": "2c26b46b68ffc68ff99b453c1d30413413...",
      "virustotal": {
        "detections": 54,
        "total_engines": 72,
        "verdict": "malicious"
      }
    }
  ],
  "risk_assessment": {
    "score": 92,
    "verdict": "malicious",
    "confidence": 95,
    "risk_factors": [
      "authentication_failure",
      "known_malicious_iocs",
      "typosquatting",
      "malicious_attachment",
      "high_risk_country",
      "newly_registered_domain"
    ]
  },
  "recommendations": [
    "quarantine_email",
    "block_sender_domain",
    "add_iocs_to_threat_feeds",
    "search_for_similar_emails",
    "notify_user",
    "report_abuse"
  ]
}
```

---

## 🔑 API Keys Setup

### VirusTotal API

1. Create account at https://www.virustotal.com/
2. Navigate to your profile → API Key
3. Copy your API key
4. Add to `config.yaml` or set environment variable:
   ```bash
   export VIRUSTOTAL_API_KEY="your_key_here"
   ```

### AbuseIPDB API

1. Register at https://www.abuseipdb.com/
2. Go to Account → API → Create Key
3. Copy your API key
4. Add to `config.yaml` or set environment variable:
   ```bash
   export ABUSEIPDB_API_KEY="your_key_here"
   ```

### URLhaus

URLhaus API is **free and requires no API key**. It's enabled by default.

---

## 🔒 Security Considerations

### ⚠️ Critical Security Warnings

1. **Isolated Environment**: Always run this tool in an isolated environment (VM, sandbox, or air-gapped system) when analyzing potentially malicious emails.

2. **Malware Risk**: Email attachments may contain active malware. **NEVER** execute or open extracted attachments on production systems.

3. **Network Exposure**: When enrichment is enabled, the tool will connect to external threat intelligence APIs. Ensure appropriate network segmentation.

4. **Data Privacy**: Emails may contain sensitive or confidential information. Comply with your organization's data handling policies and applicable privacy regulations (GDPR, HIPAA, etc.).

5. **API Key Security**: 
   - Never commit API keys to version control
   - Use environment variables or secure key management
   - Rotate API keys regularly
   - Limit API key permissions to minimum required

### Best Practices

✅ Run in dedicated analysis VM or container  
✅ Use network monitoring to track outbound connections  
✅ Sanitize reports before sharing outside security team  
✅ Maintain audit logs of all analyzed emails  
✅ Keep tool and dependencies updated  
✅ Validate tool output before taking action  
✅ Follow your organization's incident response procedures  

---

## 🛠️ Troubleshooting

### Common Issues

**Problem**: `ModuleNotFoundError: No module named 'X'`

```bash
# Solution: Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

---

**Problem**: Email parsing fails

```bash
# Solution: Verify .eml format
# Export email properly from your email client
# Ensure file is not corrupted
file suspicious_email.eml  # Should show "RFC 822 mail text"
```

---

**Problem**: API enrichment fails

```bash
# Check API key configuration
python phish_triage.py -f email.eml -v  # Verbose mode

# Verify environment variables
echo $VIRUSTOTAL_API_KEY
echo $ABUSEIPDB_API_KEY

# Test without enrichment
python phish_triage.py -f email.eml  # Enrichment disabled by default
```

---

**Problem**: Permission errors

```bash
# Fix directory permissions
chmod 755 ./reports/
chmod 755 ./samples/

# Run with appropriate user permissions
# Avoid running as root unless absolutely necessary
```

---

**Problem**: Slow processing on large batches

```bash
# Process smaller batches
find emails/ -name "*.eml" | head -100 | xargs -I {} python phish_triage.py -f {}

# Disable enrichment for faster processing
python phish_triage.py -d emails/

# Use verbose mode to identify bottlenecks
python phish_triage.py -d emails/ -v
```

---

### Getting Help

If you encounter issues not covered here:

1. 📖 Check the [GitHub Issues](https://github.com/ashishjuley10/phish-triage-kit/issues) page
2. 🔍 Search existing issues for similar problems
3. 🆕 Open a new issue with:
   - Tool version (`python phish_triage.py --version`)
   - Error messages (full traceback)
   - Steps to reproduce
   - Operating system and Python version

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Ways to Contribute

- 🐛 Report bugs and issues
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit bug fixes
- ✨ Add new threat intelligence integrations
- 🧪 Write unit tests
- ⭐ Star the repository

### Contribution Workflow

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Make** your changes and test thoroughly
4. **Commit** with clear messages: `git commit -m "Add: URLScan integration"`
5. **Push** to your fork: `git push origin feature/amazing-feature`
6. **Open** a Pull Request with detailed description

### Development Guidelines

- Follow **PEP 8** style guidelines
- Add **docstrings** to all functions
- Write **unit tests** for new features
- Update **documentation** as needed
- Keep commits **atomic** and **focused**
- Test with multiple email samples

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### MIT License Summary

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files, to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, subject to the following conditions:

- The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
- The software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.

---

## ⚖️ Disclaimer

This tool is provided for **educational and authorized security research purposes only**.

### Legal Notice

- ✅ **Authorized Use Only**: Only analyze emails you have explicit permission to examine
- ⚠️ **No Warranty**: This software is provided "as is" without warranties of any kind
- 🚫 **Liability**: The authors are not responsible for any misuse or damage caused by this tool
- 📜 **Compliance**: Users must comply with all applicable laws, regulations, and organizational policies
- 🎯 **Ethical Use**: This tool should only be used for defensive security and threat research

### Responsible Use Guidelines

- Do NOT use for unauthorized email interception or monitoring
- Respect privacy laws and data protection regulations (GDPR, CCPA, etc.)
- Obtain proper authorization before analyzing organizational emails
- Use findings responsibly and report threats through proper channels
- Follow your organization's incident response procedures
- Do NOT weaponize extracted IOCs or techniques for malicious purposes

---

## 🙏 Acknowledgments

This project leverages the following open-source libraries and threat intelligence sources:

- **Email Parsing**: Python's `email` and `email.parser` libraries
- **Threat Intelligence**: 
  - [URLhaus](https://urlhaus.abuse.ch/) by abuse.ch
  - [VirusTotal](https://www.virustotal.com/) by Chronicle Security
  - [AbuseIPDB](https://www.abuseipdb.com/) by Marathon Studios
- **Community**: Thanks to all contributors and the infosec community

---

## 📞 Contact & Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/ashishjuley10/phish-triage-kit/issues)
- **Pull Requests**: [Contribute improvements](https://github.com/ashishjuley10/phish-triage-kit/pulls)
- **Author**: [@ashishjuley10](https://github.com/ashishjuley10)

---

## 🗺️ Roadmap

### Planned Features

- [ ] **Machine Learning**: ML-based phishing detection models
- [ ] **YARA Rules**: Custom YARA rule scanning for attachments
- [ ] **MISP Integration**: Export IOCs to MISP threat sharing platform
- [ ] **Sandbox Integration**: Automated malware analysis via Cuckoo/Any.Run
- [ ] **Email Formats**: Support for .msg, .pst, and .mbox formats
- [ ] **Real-time Monitoring**: IMAP/EWS integration for live monitoring
- [ ] **Web Dashboard**: Interactive web UI for analysis and reporting
- [ ] **PDF Reports**: Generate professional PDF reports
- [ ] **Timeline Analysis**: Temporal correlation of phishing campaigns
- [ ] **Header Forgery Detection**: Advanced header manipulation detection

### Version History

**v1.0.0** (Current - January 2026)
- ✅ Initial release
- ✅ Email parsing and IOC extraction
- ✅ SPF/DKIM/DMARC analysis
- ✅ Threat intelligence enrichment (URLhaus, VT, AbuseIPDB)
- ✅ Campaign correlation
- ✅ Multiple output formats
- ✅ Batch processing

---

<div align="center">

**Made with ❤️ for SOC analysts and threat researchers**

⭐ **Star this repo** if you find it useful!

*Last Updated: January 30, 2026*

</div>
"""

# Save to output directory
output_path = '/mnt/user-data/outputs/README.md'
with open(output_path, 'w', encoding='utf-8') as f:
    f.write(improved_readme)

print("✅ README.md created successfully!")
print(f"📁 Location: {output_path}")
```

