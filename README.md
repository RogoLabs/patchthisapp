# 🛡️ PatchThisApp

<div align="center">

[![GitHub stars](https://img.shields.io/github/stars/RogoLabs/patchthisapp?style=flat-square)](https://github.com/RogoLabs/patchthisapp/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/RogoLabs/patchthisapp?style=flat-square)](https://github.com/RogoLabs/patchthisapp/issues)
[![GitHub license](https://img.shields.io/github/license/RogoLabs/patchthisapp?style=flat-square)](https://github.com/RogoLabs/patchthisapp/blob/main/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/RogoLabs/patchthisapp?style=flat-square)](https://github.com/RogoLabs/patchthisapp/commits/main)

**Enterprise-grade vulnerability intelligence and prioritization platform**

*Powered by [RogoLabs](https://rogolabs.net/) | Originally created by [Jerry Gamblin](https://www.jerrygamblin.com)*

[📊 Live Dashboard](https://patchthisapp.rogolabs.net) • [🚀 Quick Start](#quick-start) • [📖 Documentation](#documentation) • [🤝 Contributing](#contributing)

</div>

---

## 🎯 Overview

PatchThisApp transforms vulnerability management by providing **actionable intelligence** that cuts through the noise of thousands of CVEs published monthly. Our platform aggregates and analyzes data from industry-leading sources to deliver a curated, prioritized list of vulnerabilities that matter most to your organization.

### ✨ Key Features

- **🔍 Intelligent Prioritization**: ML-driven scoring and analysis to focus on the most critical threats
- **🚀 Real-time Intelligence**: Continuous monitoring and updates from trusted security sources
- **📱 Modern Web Interface**: Clean, responsive dashboard with advanced filtering and sorting
- **📊 Multiple Data Formats**: CSV export, JSON API, and web visualization
- **🎨 Enterprise Ready**: Professional interface suitable for executive reporting
- **🔧 Open Source**: Transparent, community-driven development

## 🏢 Enterprise Intelligence Sources

Our platform integrates data from the most trusted vulnerability intelligence sources:

| Source | Description | Update Frequency |
|--------|-------------|------------------|
| **[CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** | Known Exploited Vulnerabilities actively targeted in the wild | Daily |
| **[Rapid7 Metasploit](https://docs.rapid7.com/metasploit/modules/)** | Battle-tested exploit modules used by security professionals | Continuous |
| **[Project Discovery Nuclei](https://github.com/projectdiscovery/nuclei-templates)** | Community-driven vulnerability detection templates | Continuous |
| **[EPSS Scoring](https://www.first.org/epss/)** | ML-driven exploit prediction scores (>0.95 threshold) | Daily |

## 🚀 Quick Start

### Prerequisites

- Python 3.8+ (for data processing)
- Web server (for hosting static files)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/RogoLabs/patchthisapp.git
   cd patchthisapp
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Generate vulnerability data**
   ```bash
   python patchthisapp.py
   ```

4. **Serve the web interface**
   ```bash
   # Using Python's built-in server
   cd web
   python -m http.server 8000
   
   # Or using any web server of your choice
   ```

5. **Access the dashboard**
   Open your browser to `http://localhost:8000`

## 📖 Documentation


### Project Structure

```
patchthisapp/
├── 📄 patchthisapp.py          # Core data processing engine
├── 📄 requirements.txt        # Python dependencies
├── 📁 web/                    # Static web interface
│   ├── 📄 index.html          # Main landing page
│   ├── 📄 viewer.html         # Data visualization dashboard
│   ├── 📄 modern.css          # Modern styling
│   └── 📄 data.csv            # Generated vulnerability data
├── 📁 data/                   # Raw data sources
│   └── 📄 data.csv            # Processed vulnerability dataset
├── 📁 scripts/                # Helper scripts for data and analysis
│   ├── 📄 local_data.py       # Download all required data for local testing
│   └── 📄 column_summary.py   # Print summary stats for key columns
└── 📄 README.md               # This file
```

### Data Processing Engine

The `patchthisapp.py` script is the heart of our intelligence platform:

**Key Features:**
- 🔄 **Automated Data Collection**: Fetches from multiple trusted sources
- 🧹 **Data Normalization**: Standardizes formats and removes duplicates
- 📊 **Intelligent Scoring**: Applies EPSS and CVSS scoring for prioritization
- 📈 **Export Capabilities**: Generates CSV and JSON outputs
- 🔍 **Error Handling**: Robust error management and logging

**New Columns:**
- `Vendor`: The primary vendor associated with the vulnerability (from NVD CPE data)
- `Affected Products`: The main affected product(s) (from NVD CPE data)
- `CVSS_Vector`: The CVSS attack vector (e.g., NETWORK, ADJACENT, LOCAL)

**Usage:**
```bash
# Basic usage
python patchthisapp.py

# With custom output directory
python patchthisapp.py --output-dir /path/to/output

# Verbose logging
python patchthisapp.py --verbose
```

### Web Interface

Our modern web interface provides:

#### 🏠 Landing Page (`index.html`)
- Professional overview of the platform
- Data source information
- Quick access to intelligence dashboard

#### 📊 Intelligence Dashboard (`viewer.html`)
- **Sortable columns**: Click any header to sort data
- **Real-time search**: Filter vulnerabilities instantly
- **Responsive design**: Works on desktop, tablet, and mobile
- **Export functionality**: Download data as CSV
- **Professional styling**: Enterprise-ready appearance

#### Key Dashboard Features:
- **CVE Information**: Complete vulnerability identifiers
- **CVSS Scoring**: Visual severity indicators
- **EPSS Scoring**: Exploit prediction probability
- **Publication Dates**: Timeline information
- **Source Attribution**: Data provenance tracking

## 🔧 API & Data Formats

### CSV Export

The generated `data.csv` includes:
- `CVE`: CVE identifier
- `CVSS Score`: Severity score (0.0-10.0)
- `CVSS_Vector`: CVSS attack vector (e.g., NETWORK, ADJACENT, LOCAL)
- `EPSS`: Exploit prediction score (0.0-1.0)
- `Description`: Vulnerability description
- `Published`: Publication date
- `Source`: Data source attribution
- `Vendor`: Primary vendor (from NVD CPE)
- `Affected Products`: Main affected product(s) (from NVD CPE)

### JSON API

### Data Processing Engine

The `patchthisapp.py` script is the heart of our intelligence platform.

**Usage:**
```bash
# Basic usage
python patchthisapp.py

# With custom output directory
python patchthisapp.py --output-dir /path/to/output

# Verbose logging
python patchthisapp.py --verbose
```

### Helper Scripts

**Download all required data for local testing:**
```bash
python scripts/local_data.py
```
This will fetch the latest NVD, CISA KEV, Metasploit, Nuclei, and EPSS data. Supports macOS and Linux.

**Print summary statistics for Vendor, Affected Products, and CVSS_Vector columns:**
```bash
python scripts/column_summary.py
```
This will print counts, unique values, and top values for the new columns in `data/data.csv`.
```

### Custom Data Sources
Extend the platform by adding custom data sources in `patchthisapp.py`:
```python
def load_custom_source(source_url: str) -> pd.DataFrame:
    # Your custom data loading logic
    pass
```

## 🚀 Deployment

### Static Hosting
Deploy to any static hosting platform:

- **GitHub Pages**: Automatic deployment from repository
- **Netlify**: Drag-and-drop deployment
- **AWS S3**: Static website hosting
- **Cloudflare Pages**: Global CDN deployment

### Docker Deployment
```dockerfile
FROM nginx:alpine
COPY web/ /usr/share/nginx/html/
EXPOSE 80
```

### Production Considerations
- 🔒 **HTTPS**: Always use SSL in production
- 🚀 **CDN**: Implement content delivery network
- 📊 **Analytics**: Add usage tracking if needed
- 🔄 **Automation**: Schedule regular data updates

## 🤝 Contributing

We welcome contributions from the security community! Here's how you can help:

### Ways to Contribute
- 🐛 **Bug Reports**: Report issues or inconsistencies
- ✨ **Feature Requests**: Suggest new capabilities
- 📖 **Documentation**: Improve guides and examples
- 🔧 **Code Contributions**: Submit pull requests
- 📊 **Data Sources**: Suggest additional intelligence feeds

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Code Style
- Follow PEP 8 for Python code
- Use meaningful commit messages
- Include documentation for new features
- Ensure backward compatibility

## 📊 Metrics & Analytics

### Current Coverage
- **~2,000+** actively tracked CVEs
- **4** primary intelligence sources
- **24/7** monitoring and updates
- **99.9%** uptime target

### Performance
- **<2s** page load time
- **Real-time** search and filtering
- **Mobile-optimized** responsive design
- **Lightweight** ~100KB total assets

## 🔐 Security & Privacy

- **No Data Collection**: We don't track users or collect personal data
- **Open Source**: Complete transparency in methodology
- **Secure Sources**: All data from verified, trusted sources
- **Regular Updates**: Continuous security monitoring

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **[Jerry Gamblin](https://www.jerrygamblin.com)** - Original creator and vision
- **[RogoLabs](https://rogolabs.net/)** - Current maintainer and platform provider
- **Security Community** - Contributors and data source providers
- **Open Source Projects** - CISA, Rapid7, Project Discovery, and FIRST

## 📞 Support & Contact

- **🐛 Issues**: [GitHub Issues](https://github.com/RogoLabs/patchthisapp/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/RogoLabs/patchthisapp/discussions)
- **🌐 Website**: [RogoLabs](https://rogolabs.net/)
- **📧 Email**: Contact through RogoLabs website

---

<div align="center">

**Made with ❤️ by the security community**

⭐ **Star this repository** if you find it useful!

[🔝 Back to top](#-patchthisapp)

</div>
