<div align="center">

#  Threat Intelligence Aggregator

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![CI](https://img.shields.io/badge/CI-Passing-brightgreen?style=for-the-badge&logo=github-actions)](.github/workflows)
[![Tests](https://img.shields.io/badge/Tests-13%20Cases-orange?style=for-the-badge)](tests/)

**A comprehensive toolkit to collect, parse, normalize, and correlate threat intelligence indicators from multiple feeds.**

[Quick Start](#-quick-start) • [Features](#-features) • [Installation](#-installation) • [Documentation](#-documentation) • [Report](docs/UnifiedMentor_Internship_Report.md)

</div>

---

##  Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Internship Details](#-internship-details)
- [Screenshots](#-screenshots)
- [Contributing](#-contributing)
- [License](#-license)

---

##  Overview

The **Threat Intelligence Aggregator** is a Python-based toolkit developed during the **Unified Mentor Internship Program** to address the challenge of processing and correlating threat intelligence data from multiple sources.

### Problem Statement

Organizations receive threat feeds from multiple sources in different formats:
-  Open-source intelligence (OSINT) platforms
-  Commercial threat intelligence providers  
-  Security tools (SIEM, firewall, IDS logs)
-  Government CERT notifications

**Challenge**: Different formats (CSV, JSON, STIX, TXT) make analysis difficult and time-consuming.

### Solution

This toolkit provides an automated pipeline that:
1.  Accepts multiple feed formats
2.  Extracts and validates IOCs
3.  Normalizes data into a unified structure
4.  Correlates indicators across sources
5.  Generates actionable blocklists
6.  Produces comprehensive reports

---

##  Features

### Core Capabilities

| Feature | Description | Status |
|---------|-------------|--------|
| **Multi-Format Support** | Parse CSV, JSON, TXT, STIX feeds | ✅ |
| **IOC Types** | Extract IPs, domains, URLs, hashes, emails | ✅ |
| **Data Normalization** | Standardize heterogeneous data | ✅ |
| **Cross-Feed Correlation** | Detect repeated indicators | ✅ |
| **Priority Scoring** | Assign severity ratings | ✅ |
| **Blocklist Generation** | Create firewall/web filter lists | ✅ |
| **Visual Reporting** | Generate HTML dashboards | ✅ |

### Supported IOC Types

| Type | Examples | Validation |
|------|----------|------------|
| **IPv4** | `192.168.1.1` | ✅ RFC 1918 exclusion |
| **IPv6** | `2001:db8::1` | ✅ Full validation |
| **Domains** | `malware.com` | ✅ TLD check |
| **URLs** | `http://evil.com` | ✅ Schema validation |
| **MD5** | `a1b2c3...` (32 chars) | ✅ Length check |
| **SHA1** | `a1b2c3...` (40 chars) | ✅ Length check |
| **SHA256** | `a1b2c3...` (64 chars) | ✅ Length check |
| **Email** | `evil@domain.com` | ✅ Format validation |

---

##  Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    THREAT INTELLIGENCE AGGREGATOR               │
└─────────────────────────────────────────────────────────────────┘

    ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
    │ Feed Sources │────▶│ Feed Loader  │────▶│ IOC Parser   │
    │              │     │              │     │              │
    │ - Files      │     │ - CSV        │     │ - IPs        │
    │ - URLs       │     │ - JSON       │     │ - Domains    │
    │ - APIs       │     │ - STIX       │     │ - URLs       │
    └──────────────┘     └──────────────┘     └──────────────┘
                                                       │
                                                       ▼
    ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
    │ Blocklists   │◀────│ Correlation  │◀────│ Normalizer   │
    │              │     │ Engine       │     │              │
    │ - IP Lists   │     │              │     │ - Validate   │
    │ - Domains    │     │ - Match      │     │ - Enrich     │
    │ - Hashes     │     │ - Score      │     │ - Tag        │
    └──────────────┘     └──────────────┘     └──────────────┘
            │
            ▼
    ┌──────────────┐
    │   Reports    │
    │              │
    │ - JSON       │
    │ - HTML       │
    │ - TXT        │
    └──────────────┘
```

---

##  Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/threat-intelligence-aggregator.git
cd threat-intelligence-aggregator

# Install dependencies
pip install -r requirements.txt

# Run with sample data
python src/main.py --feeds data/sample_feed.txt --verbose
```

---

##  Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Step-by-Step

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/threat-intelligence-aggregator.git
cd threat-intelligence-aggregator

# 2. Create virtual environment (recommended)
python3 -m venv venv

# 3. Activate virtual environment
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Verify installation
python src/main.py --help
```

---

## 💻 Usage

### Basic Usage

```bash
# Process a single feed
python src/main.py --feeds data/sample_feed.txt

# Process multiple feeds
python src/main.py --feeds data/sample_feed.txt data/sample_feed.csv

# Process all feeds in a directory
python src/main.py --feeds data/*.txt data/*.csv data/*.json
```

### Advanced Usage

```bash
# Custom output directory with verbose logging
python src/main.py \
  --feeds data/sample_feed.txt data/sample_feed.csv \
  --output results/ \
  --verbose

# Use custom configuration
python src/main.py \
  --feeds data/sample_feed.json \
  --config my_config.json \
  --output custom_output/
```

### Command-Line Options

```
usage: main.py [-h] --feeds FEEDS [FEEDS ...] [--output OUTPUT] 
               [--config CONFIG] [--verbose]

Threat Intelligence Aggregator

optional arguments:
  -h, --help            Show help message
  --feeds FEEDS [FEEDS ...], -f FEEDS [FEEDS ...]
                        List of feed URLs or file paths
  --output OUTPUT, -o OUTPUT
                        Output directory (default: output)
  --config CONFIG, -c CONFIG
                        Config file (default: config.json)
  --verbose, -v         Enable verbose logging
```

---

##  Project Structure

```
threat-intelligence-aggregator/
├── 📁 .github/
│   └── 📁 workflows/
│       └── python-ci.yml       # GitHub Actions CI/CD
├── 📁 src/                      # Source code (~1,800 lines)
│   ├── __init__.py
│   ├── main.py                  # Main orchestrator
│   ├── feed_loader.py           # Feed loading
│   ├── ioc_parser.py            # IOC parsing
│   ├── normalizer.py            # Data normalization
│   ├── correlation_engine.py    # Correlation analysis
│   ├── blocklist_generator.py   # Blocklist generation
│   ├── report_generator.py      # Report generation
│   └── utils.py                 # Utilities
├── 📁 tests/                    # Unit tests (13 cases)
│   ├── test_ioc_parser.py
│   └── test_correlation.py
├── 📁 data/                     # Sample data files
│   ├── sample_feed.txt
│   ├── sample_feed.csv
│   └── sample_feed.json
├── 📁 docs/                     # Documentation
│   └── UnifiedMentor_Internship_Report.md
├── 📁 output/                   # Generated output (created at runtime)
├── config.json                  # Configuration
├── requirements.txt             # Dependencies
├── README.md                    # This file
├── LICENSE                      # MIT License
├── CONTRIBUTING.md              # Contribution guidelines
└── CODE_OF_CONDUCT.md           # Code of conduct
```

---

## Internship Details

<div align="center">

| Attribute | Details |
|-----------|---------|
| **Provider** | Unified Mentor |
| **Program** | Cybersecurity Internship |
| **Duration** | 3 Months |
| **Project Duration** | 2 Months |
| **Domain** | Threat Intelligence |
| **Lines of Code** | ~3,300 |
| **Test Coverage** | 13 test cases |

</div>

### Learning Outcomes

 **Python Programming**: Advanced regex, data structures, file I/O
 **Security Concepts**: IOCs, threat feeds, blocklists
-**Data Processing**: Parsing and transforming heterogeneous data
-**Software Design**: Modular architecture with separation of concerns
-**Testing**: Unit tests and validation procedures

---

## Screenshots

### Sample Output Structure

```
output/
├── blocklist_ips.txt
├── blocklist_domains.txt
├── blocklist_urls.txt
├── blocklist_hashes.csv
├── blocklist_combined.json
├── threat_report.json
├── threat_report.html
└── summary.txt
```

### Sample Summary Output

```
============================================================
THREAT INTELLIGENCE REPORT - SUMMARY
============================================================

EXECUTIVE SUMMARY
----------------------------------------
Total Indicators: 29
Critical Priority: 1
High Priority: 4
Medium Priority: 8
Low Priority: 11
Multi-Source Indicators: 5

INDICATORS BY TYPE
----------------------------------------
  IP: 5
  DOMAIN: 4
  HASH: 3
  URL: 2
  EMAIL: 1
```

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---


## 🙏 Acknowledgments

- **Unified Mentor** for providing the internship opportunity
- Open-source threat intelligence communities
- Security researchers sharing IOC data

---

<div align="center">

**Built with ❤️ during Unified Mentor Internship Program**

[⬆ Back to Top](#-threat-intelligence-aggregator)

</div>
