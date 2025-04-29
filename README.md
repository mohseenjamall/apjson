# Enhanced Web Security Scanner

## Introduction

The Enhanced Web Security Scanner is a comprehensive, automated tool designed to assess web application security through in-depth crawling, endpoint discovery, and vulnerability detection. It combines several powerful security tools into a unified, easy-to-use bash script that systematically identifies potential security risks in web applications.

![Security Scanner Banner](https://example.com/banner.png)

## Features

- **Comprehensive Crawling**: Leverages Katana for efficient web content discovery
- **JavaScript Analysis**: Extracts and analyzes JavaScript files for security vulnerabilities
- **API Endpoint Detection**: Identifies potential API endpoints and tests them for vulnerabilities
- **Parameter Testing**: Optional fuzzing of URL parameters to detect injection flaws
- **Multiple Discovery Methods**: Combined approach using direct crawling, historical data (Wayback), and other sources
- **Vulnerability Classification**: Automatic categorization of findings by severity (Critical, High, Medium, Low)
- **Interactive HTML Reports**: Generates comprehensive, easy-to-navigate HTML reports
- **Parallel Processing**: Optimized performance with configurable concurrent operations
- **Robust Error Handling**: Graceful recovery from failures with detailed logging
- **Flexible Configuration**: Customizable settings via configuration file or command-line parameters

## Requirements

### Essential Tools
- Bash (version 4.0+)
- curl
- grep
- awk
- sed
- jq
- md5sum
- openssl

### Optional Security Tools
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner
- [Katana](https://github.com/projectdiscovery/katana) - Web crawling framework
- [waybackurls](https://github.com/tomnomnom/waybackurls) - Fetch URLs from the Wayback Machine
- [gau](https://github.com/lc/gau) - Get All URLs
- [httpx](https://github.com/projectdiscovery/httpx) - HTTP toolkit
- [ffuf](https://github.com/ffuf/ffuf) - Fast web fuzzer

## Installation

### Quick Setup

1. Download the script:
```bash
curl -O https://raw.githubusercontent.com/yourusername/security-scanner/main/webscan.sh
```

2. Make it executable:
```bash
chmod +x webscan.sh
```

3. Run the script:
```bash
./webscan.sh
```

The script will check for required dependencies and guide you through installing any missing components.

### Dependencies Installation

#### Install Required System Tools

For Debian/Ubuntu:
```bash
apt update
apt install -y curl grep gawk sed jq openssl
```

For CentOS/RHEL:
```bash
yum install -y curl grep gawk sed jq openssl
```

For macOS (using Homebrew):
```bash
brew install curl grep gawk gnu-sed jq openssl
```

#### Install Go Security Tools

If you have Go installed:
```bash
# Install Nuclei
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install Katana
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Install waybackurls
go install github.com/tomnomnom/waybackurls@latest

# Install gau
go install github.com/lc/gau/v2/cmd/gau@latest

# Install httpx
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install ffuf
go install github.com/ffuf/ffuf@latest
```

Add Go bin directory to your PATH:
```bash
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

## Usage

### Basic Usage

Scan a website:
```bash
./webscan.sh https://example.com
```

The script will prompt for input if no URL is provided:
```bash
./webscan.sh
# It will then prompt: Enter target URL:
```

### Command Options

The script accepts various command-line options:

```bash
./webscan.sh [options] [URL]

Options:
  -h, --help                  Show this help message
  -v, --verbose               Increase verbosity (can be used multiple times)
  -t, --threads NUMBER        Set maximum threads (default: 8)
  -d, --depth NUMBER          Set crawl depth (default: 3)
  -o, --output DIRECTORY      Set output directory
  -c, --config FILE           Use custom config file
  --timeout SECONDS           Set scan timeout (default: 600)
  --download-timeout SECONDS  Set download timeout (default: 30)
  --enable-wayback            Enable Wayback Machine URL discovery
  --enable-gau                Enable GAU URL discovery
  --custom-templates DIR      Use custom Nuclei templates
```

### Output

The scanner creates a structured output directory containing:

```
[domain]_[timestamp]/
├── js_files/                  # JavaScript and JSON files
│   ├── js_urls.txt            # List of discovered JS files
│   ├── json_urls.txt          # List of discovered JSON files
│   └── downloaded/            # Downloaded files for analysis
├── api_endpoints/             # API-related discoveries
│   ├── api_urls.txt           # Potential API endpoints
│   ├── param_urls.txt         # URLs with parameters
│   ├── active_endpoints.txt   # Verified active endpoints
│   └── ...
├── reports/                   # Analysis reports
│   ├── critical_vulns.txt     # Critical vulnerabilities
│   ├── high_vulns.txt         # High-severity vulnerabilities
│   ├── medium_vulns.txt       # Medium-severity vulnerabilities
│   ├── low_vulns.txt          # Low-severity vulnerabilities
│   ├── report.html            # Interactive HTML report
│   ├── scan_summary.json      # JSON summary of findings
│   └── ...
├── crawl_results.txt          # All discovered URLs
├── scan_[timestamp].log       # Detailed log file
└── scan_state.json            # Scan state information
```

## Configuration

The script uses a configuration file located at `~/.webscan_config`. This file is automatically created on first run with default values:

```bash
# Web Security Scanner Configuration
MAX_THREADS=8
DOWNLOAD_TIMEOUT=30
SCAN_TIMEOUT=600
CRAWL_DEPTH=3
OUTPUT_DIR="./scan_results"
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
VERBOSE=1
ENABLE_WAYBACK=false
ENABLE_GAU=false
CUSTOM_NUCLEI_TEMPLATES=""
```

You can edit this file to customize default behavior.

## Understanding Reports

### HTML Report

The HTML report (`reports/report.html`) provides a comprehensive overview of scan results:

- **Executive Summary**: Key statistics and vulnerability counts
- **Vulnerability Details**: Collapsible sections for each severity level
- **Scan Details**: Configuration and scan parameters
- **Interactive Elements**: Expandable sections for detailed information

### Vulnerability Classification

Findings are classified into four severity levels:

1. **Critical**: Severe vulnerabilities requiring immediate attention (RCE, SQLi, etc.)
2. **High**: Significant security issues with high potential impact
3. **Medium**: Moderate security issues that should be addressed
4. **Low**: Minor security concerns with limited impact

### JSON Summary

The `reports/scan_summary.json` file contains structured data about the scan:

```json
{
  "scan_id": "abcd1234",
  "target": "https://example.com",
  "timestamp": "2023-05-01T12:34:56Z",
  "duration": "00:15:30",
  "stats": {
    "total_urls": 250,
    "js_files": 45,
    "json_files": 12,
    "api_endpoints": 18,
    "downloaded_files": 57,
    "analyzed_files": 57,
    "vulnerabilities": {
      "total": 8,
      "critical": 1,
      "high": 2,
      "medium": 3,
      "low": 2
    }
  }
}
```

## Advanced Usage

### Custom Nuclei Templates

You can use custom Nuclei templates for specialized scanning:

```bash
./webscan.sh --custom-templates /path/to/templates https://example.com
```

Or set in config:
```bash
echo 'CUSTOM_NUCLEI_TEMPLATES="/path/to/templates"' >> ~/.webscan_config
```

### Historical URL Discovery

Enable Wayback Machine and/or GAU for historical URL discovery:

```bash
./webscan.sh --enable-wayback --enable-gau https://example.com
```

### Parameter Fuzzing

The script can automatically test URL parameters for common vulnerabilities if ffuf is installed:

```bash
# This functionality is automatically used when ffuf is available
# No special flags needed
```

## Troubleshooting

### Common Issues

#### Missing Tools
If the script reports missing tools, install them as described in the Installation section.

#### Permission Denied
```bash
chmod +x webscan.sh
```

#### Network Issues
- Ensure you have active internet access
- Check if the target website is accessible
- Try increasing timeouts in the configuration file

#### High Resource Usage
- Reduce MAX_THREADS in the configuration file
- Decrease CRAWL_DEPTH for faster scanning
- Use a more focused target URL with a specific path

### Logs

Detailed logs are stored in the scan output directory:
```bash
cat [domain]_[timestamp]/scan_[timestamp].log
```

Increase verbosity for more detailed logs:
```bash
./webscan.sh --verbose --verbose https://example.com
```

## Security Considerations

- Always ensure you have proper authorization before scanning any website
- This tool is designed for security professionals and system administrators
- Unauthorized security scanning may be illegal in many jurisdictions
- Use responsibly and ethically

## Contribution

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b new-feature`
3. Commit your changes: `git commit -am 'Add new feature'`
4. Push to the branch: `git push origin new-feature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The ProjectDiscovery team for Nuclei and Katana
- Tom Hudson for waybackurls
- Corben Leo for gau
- The ffuf team for the fast web fuzzer
- All open-source security tools that made this project possible

## Contact

For questions, feedback, or issues, please open an issue on the GitHub repository.

---

*Disclaimer: This tool is provided for educational and legitimate security testing purposes only. The authors are not responsible for any misuse or damage caused by this program. Always ensure you have proper authorization before conducting security testing.*
