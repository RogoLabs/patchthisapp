# PatchThisApp

Curated vulnerability intelligence aggregating data from CISA KEV, Metasploit, Nuclei templates, and EPSS scores.

[![GitHub license](https://img.shields.io/github/license/RogoLabs/patchthisapp?style=flat-square)](https://github.com/RogoLabs/patchthisapp/blob/main/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/RogoLabs/patchthisapp?style=flat-square)](https://github.com/RogoLabs/patchthisapp/commits/main)

Part of the [RogoLabs](https://rogolabs.net/) network | Originally created by [Jerry Gamblin](https://www.jerrygamblin.com)

**Live Dashboard**: https://patchthis.app

---

## Overview

PatchThisApp aggregates vulnerability data from four trusted intelligence sources and presents it as a filterable, sortable dataset. The platform focuses exclusively on vulnerabilities with active exploits, public proof-of-concepts, or high EPSS scores (>0.90), filtering out noise from the ~25,000+ CVEs published annually.

### Core Capabilities

- Aggregates data from CISA KEV, Metasploit modules, Nuclei templates, and EPSS predictions
- Client-side data processing - 100% static HTML/JS/CSS
- CSV export functionality for integration with existing workflows
- Interactive analytics dashboard with Chart.js visualizations
- Sortable/filterable table view with 6-month historical data
- Updates every 6 hours via automated GitHub Actions

## Data Sources

| Source | Type | Update Frequency | Filter Criteria |
|--------|------|------------------|-----------------|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities | Daily | Active exploitation confirmed |
| [Rapid7 Metasploit](https://docs.rapid7.com/metasploit/modules/) | Exploit modules | Continuous | Public exploit module exists |
| [Project Discovery Nuclei](https://github.com/projectdiscovery/nuclei-templates) | Detection templates | Continuous | Detection template available |
| [EPSS](https://www.first.org/epss/) | Exploit prediction | Daily | EPSS score > 0.90 |

### Data Collection Process

1. Python script (`patchthisapp.py`) fetches data from all four sources
2. CVE data enriched with NVD information (CVSS scores, vectors, CPEs)
3. Duplicate CVEs across sources are merged with source attribution preserved
4. Dataset filtered to last 6 months of published vulnerabilities
5. Output generated as CSV for web interface consumption

## Installation

### Requirements

- Python 3.8+
- Dependencies: `requests`, `pandas`

### Local Setup

```bash
# Clone repository
git clone https://github.com/RogoLabs/patchthisapp.git
cd patchthisapp

# Install dependencies
pip install -r requirements.txt

# Generate data
python patchthisapp.py

# Serve locally
cd web && python -m http.server 8000
# Access at http://localhost:8000
```

## Project Structure

```
patchthisapp/
├── patchthisapp.py          # Data aggregation script
├── requirements.txt         # Python dependencies
├── web/                     # Static site files
│   ├── index.html           # Homepage
│   ├── dashboard.html       # Analytics dashboard
│   ├── viewer.html          # Data table explorer
│   ├── modern.css           # Site styling
│   └── data.csv             # Generated dataset
├── data/                    # Output directory
│   └── data.csv             # Processed dataset
└── scripts/                 # Helper utilities
    ├── local_data.py        # Local data fetcher
    └── column_summary.py    # Column statistics
```

## Data Processing

### Script: `patchthisapp.py`

Primary data aggregation script that:

1. Fetches data from CISA KEV, Metasploit, Nuclei, and EPSS APIs
2. Queries NVD API for CVE enrichment (CVSS, vectors, CPE data)
3. Normalizes and deduplicates entries
4. Extracts vendor and product information from CPE strings
5. Generates CSV output with merged source attribution

### Output Schema

The generated `data.csv` contains:

| Column | Type | Description | Example |
|--------|------|-------------|---------|
| CVE | string | CVE identifier | CVE-2024-1234 |
| CVSS Score | float | Base score 0.0-10.0 | 9.8 |
| CVSS_Vector | string | Attack vector | NETWORK, ADJACENT, LOCAL |
| EPSS | float | Exploit probability 0.0-1.0 | 0.96 |
| Description | string | Vulnerability description | Remote code execution... |
| Published | date | Publication date | 2024-01-15 |
| Source | string | Source attribution | CISA/Metasploit/Nuclei/EPSS |
| CPE | string | Common Platform Enumeration | cpe:2.3:a:vendor:product... |
| CWE | string | Common Weakness Enumeration | CWE-79 |

### CLI Usage

```bash
# Standard run
python patchthisapp.py

# Custom output directory
python patchthisapp.py --output-dir /path/to/output

# Verbose logging
python patchthisapp.py --verbose
```

## Web Interface

### Pages

**index.html** - Landing page with project overview and data source information

**dashboard.html** - Interactive analytics dashboard featuring:
- Vulnerability timeline (6-month trend)
- Intelligence feed overlap analysis
- CVSS score distribution
- Attack vector breakdown
- EPSS risk level categorization
- Top affected products

**viewer.html** - Sortable/filterable data table with:
- Client-side search across all fields
- Column sorting (CVE, CVSS, EPSS, Published, Source)
- CSV download functionality
- Overview statistics section

## Helper Scripts

### scripts/local_data.py

Downloads latest data from all sources for local testing:
```bash
python scripts/local_data.py
```
Fetches NVD, CISA KEV, Metasploit, Nuclei, and EPSS data. Supports macOS and Linux.

### scripts/column_summary.py

Prints statistics for dataset columns:
```bash
python scripts/column_summary.py
```
Outputs counts, unique values, and top entries for `data/data.csv`.

## Deployment

### GitHub Pages

Configured for automatic deployment via GitHub Actions. Updates run every 6 hours.

### Docker

```dockerfile
FROM nginx:alpine
COPY web/ /usr/share/nginx/html/
EXPOSE 80
```

### Static Hosting Options

Compatible with any static hosting platform:
- GitHub Pages
- Netlify
- Cloudflare Pages
- AWS S3 + CloudFront
- Vercel

## Technical Architecture

- **Frontend**: Pure HTML/CSS/JS (no build process required)
- **Charts**: Chart.js 4.4.0 (loaded via CDN)
- **Data Parsing**: PapaParse 5.4.1 (client-side CSV parsing)
- **Backend**: Python 3.8+ data aggregation script
- **Hosting**: Static files only, no server-side processing
- **Updates**: Automated via GitHub Actions (every 6 hours)

## Contributing

Contributions welcome. Submit pull requests to the main branch.

### Development
1. Fork repository
2. Create feature branch
3. Make changes
4. Submit pull request

### Code Standards
- Python: PEP 8 compliance
- JavaScript: Standard ES6+
- Commits: Descriptive commit messages
- Documentation: Update README for new features

## License

MIT License - see [LICENSE](LICENSE) file.

## Maintainers

- [Jerry Gamblin](https://www.jerrygamblin.com) - Original creator
- [RogoLabs](https://rogolabs.net/) - Current maintainer

Part of the RogoLabs vulnerability intelligence network alongside [cve.icu](https://cve.icu) and [cnascorecard](https://github.com/RogoLabs/cnascorecard).

## Support

- Issues: [GitHub Issues](https://github.com/RogoLabs/patchthisapp/issues)
- Website: https://rogolabs.net
