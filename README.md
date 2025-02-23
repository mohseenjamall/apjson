# apjsonon

apjsonon is a powerful and lightweight command-line tool designed for security researchers and web developers to extract, download, and analyze JavaScript, JSON, and API-related links from a target website. It leverages `katana` for link extraction and `nuclei` for vulnerability apjsonning, providing a streamlined workflow for web security assessments.

## ✨ Features
- **Link Extraction**: Extracts JavaScript (`.js`), JSON (`.json`), and API-related links from any given URL.
- **File Download**: Downloads extracted JS and JSON files for further analysis.
- **Vulnerability apjsonning**: Performs automated vulnerability checks on downloaded files using `nuclei`.
- **Smart Processing**: Only processes file types that are detected, skipping unnecessary steps if no relevant files are found.
- **Progress Tracking**: Displays a progress bar (0% to 100%) during `nuclei` analysis.
- **Custom Output**: Saves results in a timestamped folder for easy tracking and review.

## 🛠️ Prerequisites
To run apjsonon, ensure you have the following installed on your system:
- **Operating System**: Linux-based (e.g., Ubuntu, Debian, CentOS).
- **Dependencies**:
  - `katana`: For extracting links from the target URL.
  - `nuclei`: For vulnerability apjsonning of downloaded files.
  - `curl`: For downloading files.
  - `awk`: For filtering extracted links.

## 📦 Installation
Follow these steps to set up apjsonon on your system:

1. **Clone the Repository**:
   bash
   git clone https://github.com/mohseenjamall/apjson
   cd apjsono

2. ## Install katana and nuclei via Go

	go install github.com/projectdiscovery/katana/cmd/katana@latest
	
	go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

	## Install curl and awk (usually pre-installed on Linux)
	sudo apt-get install curl awk  # On Ubuntu/Debian
	## OR
	sudo yum install curl awk   # On CentOS/RHEL

	## Add Go binaries to PATH

	export PATH=$PATH:$(go env GOPATH)/bin
	
	`chmod +x apjsonon.sh`

##  🚀 Usage
	`./apjson.sh`

	Input: Enter a valid URL (e.g., https://books.toscrape.com).
	Process:
	Extracts JS, JSON, and API links using katana.
	Downloads detected JS and JSON files (if any).
	Analyzes downloaded files with nuclei for vulnerabilities (if files exist).
	Output: Results are saved in a folder named [target]_[timestamp] (e.g., books_20250223_045008).

## Example Run

	$ ./apjson.sh
	Enter target URL: https://books.toscrape.com
	[2025-02-23 04:50:53] Creating output directory: ./books_20250223_045008
	[2025-02-23 04:50:53] Extracting links from https://books.toscrape.com using katana...
	[2025-02-23 04:50:53] JavaScript files: 4
	[2025-02-23 04:50:53] JSON files: 0
	[2025-02-23 04:50:53] API links: 0
	[2025-02-23 04:50:53] Extracted JavaScript links:
	[2025-02-23 04:50:53]   https://books.toscrape.com/static/oscar/js/bootstrap3/bootstrap.min.js
	[2025-02-23 04:50:53] Downloading JavaScript and JSON files...
	[2025-02-23 04:50:53] Successfully downloaded 4 files
	[2025-02-23 04:50:53] Analyzing files with nuclei...
	Nuclei analysis in progress: [100%]
	[2025-02-23 04:50:54] apjson completed successfully!
	
## 📂 Output Structure

	katana_output.txt: Raw links extracted by katana.
	js_files/js_urls.txt: List of extracted JavaScript URLs (if any).
	js_files/json_urls.txt: List of extracted JSON URLs (if any).
	js_files/api_urls.txt: List of extracted API URLs (if any).
	js_files/downloaded/: Folder containing downloaded JS and JSON files.
	nuclei_results.txt: Vulnerability scan results from nuclei (if applicable).
	scan_[timestamp].log: Detailed log of the entire scan process.
	
## ⚙️ How It Works

	Extraction: Uses katana to scrape the target URL for JS, JSON, and API links.
	Filtering: Only creates URL files for types that are detected (e.g., no json_urls.txt if no JSON links).
	Downloading: Downloads JS and JSON files using curl if they exist.
	Analysis: Scans downloaded files with nuclei if any files were successfully downloaded, showing a progress bar.
	Summary: Generates a summary of extracted files and potential vulnerabilities.
	
## ⚠️ Notes

	Ensure your system has an active internet connection.
	Add the Go binaries path ($(go env GOPATH)/bin) to your shell profile (e.g., .bashrc) for persistent access:
	echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
	source ~/.bashrc