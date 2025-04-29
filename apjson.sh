#!/bin/bash
set -eo pipefail

# ===============================================
# Enhanced Web Security Scanner
# A comprehensive tool for web application security assessment
# ===============================================

# ================ CONFIGURATION ================
VERSION="2.0.0"
CONFIG_FILE="${HOME}/.webscan_config"
DEFAULT_MAX_THREADS=8
DEFAULT_DOWNLOAD_TIMEOUT=30
DEFAULT_SCAN_TIMEOUT=600
DEFAULT_CRAWL_DEPTH=3
DEFAULT_OUTPUT_DIR="./scan_results"
DEFAULT_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36"

# ================ COLOR DEFINITIONS ================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m'

# ================ GLOBAL VARIABLES ================
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR=""
TOTAL_LINKS=0
TOTAL_FILES=0
DOWNLOADED_COUNT=0
VULN_COUNT=0
START_TIME=$(date +%s)
SCAN_ID=$(openssl rand -hex 8)

# ================ DEPENDENCIES ================
REQUIRED_TOOLS=("curl" "grep" "awk" "sed" "jq" "md5sum" "openssl")
OPTIONAL_TOOLS=("nuclei" "katana" "waybackurls" "gau" "httpx" "ffuf")
GO_TOOLS=("github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
          "github.com/projectdiscovery/katana/cmd/katana@latest"
          "github.com/tomnomnom/waybackurls@latest"
          "github.com/lc/gau/v2/cmd/gau@latest"
          "github.com/projectdiscovery/httpx/cmd/httpx@latest"
          "github.com/ffuf/ffuf@latest")

# ================ SIGNAL HANDLING ================
cleanup() {
    local exit_code=$?
    log_message "Cleaning up temporary files..."
    
    # Save scan state if interrupted
    if [ $exit_code -ne 0 ] && [ -d "$OUTPUT_DIR" ]; then
        echo "{\"scan_id\":\"$SCAN_ID\",\"status\":\"interrupted\",\"progress\":\"$SCAN_PROGRESS\",\"timestamp\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\"}" > "${OUTPUT_DIR}/scan_state.json"
        log_message "${YELLOW}Scan interrupted. State saved to ${OUTPUT_DIR}/scan_state.json${NC}"
    fi
    
    # Remove temp directory if it exists
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
    
    # Calculate and display execution time
    if [ -n "$START_TIME" ]; then
        END_TIME=$(date +%s)
        EXECUTION_TIME=$((END_TIME - START_TIME))
        HOURS=$((EXECUTION_TIME / 3600))
        MINUTES=$(( (EXECUTION_TIME % 3600) / 60 ))
        SECONDS=$((EXECUTION_TIME % 60))
        
        if [ $exit_code -eq 0 ]; then
            log_message "${GREEN}Scan completed successfully in ${HOURS}h ${MINUTES}m ${SECONDS}s${NC}"
        else
            log_message "${RED}Scan exited with code $exit_code after ${HOURS}h ${MINUTES}m ${SECONDS}s${NC}"
        fi
    fi
    
    exit $exit_code
}

handle_error() {
    local line=$1
    local status=$2
    log_message "${RED}Error occurred at line $line (Status: $status)${NC}"
    exit $status
}

trap 'cleanup' EXIT
trap 'handle_error $LINENO $?' ERR

# ================ UTILITY FUNCTIONS ================
log_message() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_level="INFO"
    
    # Check if the first parameter is a log level flag
    case "$1" in
        "--debug"|"--info"|"--warn"|"--error"|"--critical")
            case "$1" in
                "--debug")    log_level="DEBUG"   ; shift ;;
                "--info")     log_level="INFO"    ; shift ;;
                "--warn")     log_level="WARNING" ; shift ;;
                "--error")    log_level="ERROR"   ; shift ;;
                "--critical") log_level="CRITICAL"; shift ;;
            esac
            ;;
    esac
    
    # Determine color based on log level
    local color=""
    case "$log_level" in
        "DEBUG")    color="$GRAY"     ;;
        "INFO")     color="$NC"       ;;
        "WARNING")  color="$YELLOW"   ;;
        "ERROR")    color="$RED"      ;;
        "CRITICAL") color="$RED$BOLD" ;;
    esac
    
    # Format the log message
    local message="[$timestamp] [$log_level] $1"
    
    # Print to console with color if we have a TTY
    if [ -t 1 ]; then
        echo -e "${color}${message}${NC}" >&1
    else
        echo "$message" >&1
    fi
    
    # Always write to log file without color codes if LOG_FILE is defined
    if [ -n "$LOG_FILE" ]; then
        echo "$message" | sed 's/\x1B\[[0-9;]*[JKmsu]//g' >> "$LOG_FILE"
    fi
}

debug_message() {
    if [ "$VERBOSE" -ge 2 ]; then
        log_message "--debug" "$1"
    fi
}

show_banner() {
    echo -e "${BLUE}╔═══════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║ ${GREEN}Enhanced Web Security Scanner v${VERSION}${BLUE}          ║${NC}"
    echo -e "${BLUE}║ ${CYAN}Scan ID: ${SCAN_ID}${BLUE}                       ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"
}

check_dependencies() {
    local missing_tools=()
    local missing_go_tools=()
    
    # Check required system tools
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    # Handle missing required tools
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_message "--error" "Missing required tools: ${missing_tools[*]}"
        log_message "Please install these tools before running this script."
        exit 1
    fi
    
    # Check optional tools
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            if [ "$tool" = "katana" ] && command -v "$(go env GOPATH)/bin/katana" &> /dev/null; then
                KATANA_CMD="$(go env GOPATH)/bin/katana"
            elif [ "$tool" = "nuclei" ] && command -v "$(go env GOPATH)/bin/nuclei" &> /dev/null; then
                NUCLEI_CMD="$(go env GOPATH)/bin/nuclei"
            else
                missing_go_tools+=("$tool")
            fi
        else
            case "$tool" in
                "katana") KATANA_CMD="$tool" ;;
                "nuclei") NUCLEI_CMD="$tool" ;;
            esac
        fi
    done
    
    # Handle missing Go tools
    if [ ${#missing_go_tools[@]} -gt 0 ]; then
        log_message "--warn" "Missing optional tools: ${missing_go_tools[*]}"
        
        if command -v "go" &> /dev/null; then
            log_message "Would you like to install the missing Go tools? (y/n)"
            read -r install_choice
            
            if [[ "$install_choice" =~ ^[Yy]$ ]]; then
                for tool in "${GO_TOOLS[@]}"; do
                    tool_name=$(echo "$tool" | awk -F'/' '{print $NF}' | awk -F'@' '{print $1}')
                    if [[ " ${missing_go_tools[*]} " =~ " ${tool_name} " ]]; then
                        log_message "Installing $tool_name..."
                        go install "$tool"
                        if [ $? -eq 0 ]; then
                            log_message "${GREEN}Successfully installed $tool_name${NC}"
                            # Update command paths for key tools
                            case "$tool_name" in
                                "katana") KATANA_CMD="$(go env GOPATH)/bin/katana" ;;
                                "nuclei") NUCLEI_CMD="$(go env GOPATH)/bin/nuclei" ;;
                            esac
                        else
                            log_message "--error" "Failed to install $tool_name"
                        fi
                    fi
                done
            fi
        else
            log_message "Go is not installed. Please install Go and then install the missing tools."
            log_message "You can install the tools with: go install TOOL@latest"
        fi
    fi
    
    # Verify critical tools
    if [ -z "$KATANA_CMD" ] || [ -z "$NUCLEI_CMD" ]; then
        log_message "--error" "Critical tools are missing. Please install katana and nuclei."
        exit 1
    fi
}

load_config() {
    # Create default config if it doesn't exist
    if [ ! -f "$CONFIG_FILE" ]; then
        log_message "--debug" "Creating default configuration file at $CONFIG_FILE"
        cat > "$CONFIG_FILE" << EOL
# Web Security Scanner Configuration
MAX_THREADS=$DEFAULT_MAX_THREADS
DOWNLOAD_TIMEOUT=$DEFAULT_DOWNLOAD_TIMEOUT
SCAN_TIMEOUT=$DEFAULT_SCAN_TIMEOUT
CRAWL_DEPTH=$DEFAULT_CRAWL_DEPTH
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
USER_AGENT="$DEFAULT_USER_AGENT"
VERBOSE=1
ENABLE_WAYBACK=false
ENABLE_GAU=false
CUSTOM_NUCLEI_TEMPLATES=""
EOL
    fi
    
    # Source the config file
    if [ -f "$CONFIG_FILE" ]; then
        # shellcheck source=/dev/null
        source "$CONFIG_FILE"
    fi
    
    # Set defaults for any unset variables
    MAX_THREADS=${MAX_THREADS:-$DEFAULT_MAX_THREADS}
    DOWNLOAD_TIMEOUT=${DOWNLOAD_TIMEOUT:-$DEFAULT_DOWNLOAD_TIMEOUT}
    SCAN_TIMEOUT=${SCAN_TIMEOUT:-$DEFAULT_SCAN_TIMEOUT}
    CRAWL_DEPTH=${CRAWL_DEPTH:-$DEFAULT_CRAWL_DEPTH}
    OUTPUT_DIR=${OUTPUT_DIR:-$DEFAULT_OUTPUT_DIR}
    USER_AGENT=${USER_AGENT:-$DEFAULT_USER_AGENT}
    VERBOSE=${VERBOSE:-1}
    ENABLE_WAYBACK=${ENABLE_WAYBACK:-false}
    ENABLE_GAU=${ENABLE_GAU:-false}
    CUSTOM_NUCLEI_TEMPLATES=${CUSTOM_NUCLEI_TEMPLATES:-""}
}

validate_url() {
    local url="$1"
    
    # Basic URL validation
    if [[ ! "$url" =~ ^https?:// ]]; then
        log_message "--error" "Invalid URL format: $url"
        log_message "URL must begin with http:// or https://"
        return 1
    fi
    
    # Advanced validation - check if the URL is reachable
    if ! curl --silent --head --max-time 10 --output /dev/null --location "$url"; then
        log_message "--warn" "Warning: URL may not be reachable: $url"
        log_message "Do you want to continue anyway? (y/n)"
        read -r continue_choice
        if [[ ! "$continue_choice" =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi
    
    return 0
}

show_progress() {
    local current="$1"
    local total="$2"
    local prefix="$3"
    local suffix="${4:-}"
    local width=50
    
    # Handle division by zero
    if [ "$total" -eq 0 ]; then
        total=1
    fi
    
    # Calculate percentage and bar
    local percent=$((current * 100 / total))
    [ "$percent" -gt 100 ] && percent=100
    
    local filled_width=$((width * percent / 100))
    local empty_width=$((width - filled_width))
    
    # Create the progress bar
    local bar="["
    for ((i=0; i<filled_width; i++)); do bar+="="; done
    if [ "$filled_width" -lt "$width" ]; then bar+=">"; empty_width=$((empty_width-1)); fi
    for ((i=0; i<empty_width; i++)); do bar+=" "; done
    bar+="]"
    
    # Create info text
    local info="${percent}% (${current}/${total})"
    
    # Print progress bar
    printf "\r%s %s %s %s" "$prefix" "$bar" "$info" "$suffix"
    
    # New line if complete
    if [ "$current" -eq "$total" ]; then
        echo
    fi
}

elapsed_time() {
    local start_time="$1"
    local current_time
    current_time=$(date +%s)
    local elapsed=$((current_time - start_time))
    
    local hours=$((elapsed / 3600))
    local minutes=$(( (elapsed % 3600) / 60 ))
    local seconds=$((elapsed % 60))
    
    printf "%02d:%02d:%02d" "$hours" "$minutes" "$seconds"
}

format_file_size() {
    local size="$1"
    
    if [ "$size" -lt 1024 ]; then
        echo "${size}B"
    elif [ "$size" -lt 1048576 ]; then
        echo "$((size / 1024))KB"
    elif [ "$size" -lt 1073741824 ]; then
        echo "$((size / 1048576))MB"
    else
        echo "$((size / 1073741824))GB"
    fi
}

count_lines() {
    local file="$1"
    
    if [ -f "$file" ]; then
        wc -l < "$file" | tr -d ' ' || echo 0
    else
        echo 0
    fi
}

# ================ CORE SCANNING FUNCTIONS ================
setup_directories() {
    local target_name="$1"
    
    # Create a timestamp-based output directory
    OUTPUT_DIR="${OUTPUT_DIR}/${target_name}_${TIMESTAMP}"
    JS_DIR="${OUTPUT_DIR}/js_files"
    API_DIR="${OUTPUT_DIR}/api_endpoints"
    REPORTS_DIR="${OUTPUT_DIR}/reports"
    LOG_FILE="${OUTPUT_DIR}/scan_${TIMESTAMP}.log"
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    
    # Create all required directories
    for dir in "$OUTPUT_DIR" "$JS_DIR" "$JS_DIR/downloaded" "$API_DIR" "$REPORTS_DIR"; do
        mkdir -p "$dir" || {
            log_message "--error" "Failed to create directory: $dir"
            exit 1
        }
    done
    
    # Create state file
    echo "{\"scan_id\":\"$SCAN_ID\",\"target\":\"$TARGET_URL\",\"start_time\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\",\"status\":\"running\"}" > "${OUTPUT_DIR}/scan_state.json"
    
    log_message "Created output directory: ${OUTPUT_DIR}"
    log_message "Log file: ${LOG_FILE}"
}

crawl_target() {
    local url="$1"
    local output_file="${OUTPUT_DIR}/crawl_results.txt"
    local katana_start_time
    katana_start_time=$(date +%s)
    
    log_message "Starting crawling of $url using Katana..."
    log_message "--debug" "Using command: $KATANA_CMD with depth $CRAWL_DEPTH and $MAX_THREADS threads"
    
    # Run Katana with enhanced parameters
    $KATANA_CMD \
        -u "$url" \
        -d "$CRAWL_DEPTH" \
        -c "$MAX_THREADS" \
        -jc \
        -H "User-Agent: $USER_AGENT" \
        -rl 160 \
        -timeout "$SCAN_TIMEOUT" \
        -o "$output_file" \
        -silent 2>/dev/null
    
    local katana_status=$?
    local katana_elapsed
    katana_elapsed=$(elapsed_time "$katana_start_time")
    
    # Check Katana status
    if [ $katana_status -ne 0 ] || [ ! -s "$output_file" ]; then
        log_message "--error" "Katana crawling failed or produced no results (Status: $katana_status)"
        log_message "--warn" "Trying alternative crawling method..."
        
        # Fallback to curl and link extraction
        log_message "Fetching initial page with curl..."
        local curl_output="${TEMP_DIR}/curl_output.html"
        
        if curl -s -L --max-time 30 -A "$USER_AGENT" -o "$curl_output" "$url"; then
            # Extract links from the HTML
            grep -o 'href="[^"]*"' "$curl_output" | 
            sed 's/href="//' | 
            sed 's/"//' | 
            grep -v '^#' | 
            grep -v '^javascript:' | 
            grep -v '^mailto:' | 
            grep -v '^tel:' > "$output_file"
            
            # Make all relative URLs absolute
            sed -i "s|^/|$(echo "$url" | grep -o 'https\?://[^/]*')/|" "$output_file"
            sed -i -E "s|^(?!https?://)|$url/|" "$output_file"
            
            local found_links
            found_links=$(count_lines "$output_file")
            log_message "Extracted $found_links links with fallback method"
        else
            log_message "--error" "All crawling methods failed for $url"
            return 1
        fi
    else
        local found_urls
        found_urls=$(count_lines "$output_file")
        log_message "${GREEN}Katana found $found_urls URLs in $katana_elapsed${NC}"
    fi
    
    # Additional sources if enabled
    if [ "$ENABLE_WAYBACK" = true ] && command -v waybackurls &> /dev/null; then
        log_message "Fetching historical URLs from Wayback Machine..."
        local domain
        domain=$(echo "$url" | sed -e 's/https\?:\/\///' -e 's/\/.*$//' -e 's/:[0-9]\+$//')
        
        waybackurls "$domain" > "${OUTPUT_DIR}/wayback_urls.txt" 2>/dev/null
        local wayback_count
        wayback_count=$(count_lines "${OUTPUT_DIR}/wayback_urls.txt")
        
        if [ "$wayback_count" -gt 0 ]; then
            log_message "Found $wayback_count historical URLs from Wayback Machine"
            cat "${OUTPUT_DIR}/wayback_urls.txt" >> "$output_file"
            sort -u "$output_file" -o "$output_file"
        fi
    fi
    
    if [ "$ENABLE_GAU" = true ] && command -v gau &> /dev/null; then
        log_message "Fetching URLs with GAU..."
        local domain
        domain=$(echo "$url" | sed -e 's/https\?:\/\///' -e 's/\/.*$//' -e 's/:[0-9]\+$//')
        
        gau "$domain" --threads "$MAX_THREADS" > "${OUTPUT_DIR}/gau_urls.txt" 2>/dev/null
        local gau_count
        gau_count=$(count_lines "${OUTPUT_DIR}/gau_urls.txt")
        
        if [ "$gau_count" -gt 0 ]; then
            log_message "Found $gau_count URLs with GAU"
            cat "${OUTPUT_DIR}/gau_urls.txt" >> "$output_file"
            sort -u "$output_file" -o "$output_file"
        fi
    fi
    
    # Final URL count after all sources
    TOTAL_LINKS=$(count_lines "$output_file")
    log_message "${GREEN}Total unique URLs discovered: $TOTAL_LINKS${NC}"
    
    # Check if we found any URLs
    if [ "$TOTAL_LINKS" -eq 0 ]; then
        log_message "--warn" "No URLs discovered. Scan may not produce useful results."
        return 1
    fi
    
    return 0
}

extract_endpoints() {
    local crawl_file="$1"
    
    log_message "Extracting JavaScript, JSON, and API endpoints..."
    
    # Initialize counters
    local js_count=0
    local json_count=0
    local api_count=0
    
    if [ -s "$crawl_file" ]; then
        # JavaScript files
        grep -E 'https?://[^[:space:]]*\.js([?#][^[:space:]]*)?$' "$crawl_file" | sort -u > "${JS_DIR}/js_urls.txt"
        js_count=$(count_lines "${JS_DIR}/js_urls.txt")
        
        # JSON files
        grep -E 'https?://[^[:space:]]*\.json([?#][^[:space:]]*)?$' "$crawl_file" | sort -u > "${JS_DIR}/json_urls.txt"
        json_count=$(count_lines "${JS_DIR}/json_urls.txt")
        
        # API endpoints with enhanced patterns
        grep -E 'https?://[^[:space:]]*(/(api|v[0-9]+|rest|graphql|swagger|docs/api|endpoint|service))(/[^[:space:]]*)?$' "$crawl_file" | 
        sort -u > "${API_DIR}/api_urls.txt"
        api_count=$(count_lines "${API_DIR}/api_urls.txt")
        
        # Additional patterns that might indicate API endpoints
        grep -E 'https?://[^[:space:]]*/[^[:space:]]*\.(php|aspx|jsp|do|action)([?#][^[:space:]]*)?$' "$crawl_file" |
        sort -u > "${API_DIR}/web_endpoints.txt"
        local web_count
        web_count=$(count_lines "${API_DIR}/web_endpoints.txt")
        
        # Endpoints with query parameters
        grep -E 'https?://[^[:space:]]*\?[^[:space:]]*=' "$crawl_file" |
        sort -u > "${API_DIR}/param_urls.txt"
        local param_count
        param_count=$(count_lines "${API_DIR}/param_urls.txt")
        
        # Combine all API-like endpoints
        cat "${API_DIR}/api_urls.txt" "${API_DIR}/web_endpoints.txt" "${API_DIR}/param_urls.txt" |
        sort -u > "${API_DIR}/all_endpoints.txt"
        local all_api_count
        all_api_count=$(count_lines "${API_DIR}/all_endpoints.txt")
        
        log_message "Found endpoints:"
        log_message "- JavaScript files: ${js_count}"
        log_message "- JSON files: ${json_count}"
        log_message "- API endpoints: ${api_count}"
        log_message "- Web endpoints: ${web_count}"
        log_message "- Parameterized URLs: ${param_count}"
        log_message "- Total potential endpoints: ${all_api_count}"
        
        # Save statistics
        echo "{
            \"js_files\": $js_count,
            \"json_files\": $json_count,
            \"api_endpoints\": $api_count,
            \"web_endpoints\": $web_count,
            \"param_urls\": $param_count,
            \"total_endpoints\": $all_api_count
        }" > "${OUTPUT_DIR}/endpoint_stats.json"
    else
        log_message "--warn" "Crawl results file is empty or not found"
        touch "${JS_DIR}/js_urls.txt" "${JS_DIR}/json_urls.txt" "${API_DIR}/api_urls.txt"
    fi
    
    # Check if we have any endpoints
    if [ "$js_count" -eq 0 ] && [ "$json_count" -eq 0 ] && [ "$api_count" -eq 0 ]; then
        log_message "--warn" "No JavaScript, JSON, or API endpoints found"
        return 1
    fi
    
    return 0
}

download_files() {
    log_message "Downloading JavaScript and JSON files..."
    
    local js_count
    local json_count
    local download_start_time
    js_count=$(count_lines "${JS_DIR}/js_urls.txt")
    json_count=$(count_lines "${JS_DIR}/json_urls.txt")
    download_start_time=$(date +%s)
    
    # Function to download a file with advanced error handling
    download_file() {
        local url="$1"
        local ext="$2"
        local output_dir="$3"
        
        # Create a safe filename based on URL hash
        local filename="${output_dir}/$(echo "$url" | md5sum | cut -c 1-32)${ext}"
        
        # Try to download with retry and timeout
        local retries=2
        local retry_count=0
        local success=false
        
        while [ "$retry_count" -lt "$retries" ] && [ "$success" = false ]; do
            if curl -s -L --max-time "$DOWNLOAD_TIMEOUT" -A "$USER_AGENT" -w "%{http_code}" -o "$filename.tmp" "$url" > "${TEMP_DIR}/curl_status" 2>/dev/null; then
                local status
                status=$(cat "${TEMP_DIR}/curl_status")
                
                if [ "$status" -ge 200 ] && [ "$status" -lt 300 ] && [ -s "$filename.tmp" ]; then
                    mv "$filename.tmp" "$filename"
                    echo "success:$url:$filename"
                    success=true
                else
                    retry_count=$((retry_count + 1))
                    
                    if [ "$retry_count" -ge "$retries" ]; then
                        echo "failed:$url:HTTP $status"
                    else
                        sleep 1  # Short delay before retry
                    fi
                    
                    # Clean up the temp file
                    if [ -f "$filename.tmp" ]; then
                        rm "$filename.tmp"
                    fi
                fi
            else
                retry_count=$((retry_count + 1))
                
                if [ "$retry_count" -ge "$retries" ]; then
                    echo "failed:$url:connection error"
                else
                    sleep 1  # Short delay before retry
                fi
                
                # Clean up the temp file
                if [ -f "$filename.tmp" ]; then
                    rm "$filename.tmp"
                fi
            fi
        done
    }
    
    # Parallel downloads of JS files
    local total_to_download=$((js_count + json_count))
    local downloaded=0
    local js_downloaded=0
    local json_downloaded=0
    local js_failed=0
    local json_failed=0
    
    export -f download_file  # Export for xargs
    
    # Helper function for handling download progress
    process_download_results() {
        local results_file="$1"
        local type="$2"
        local success_count=0
        local fail_count=0
        
        while IFS=: read -r status url filename; do
            if [ "$status" = "success" ]; then
                success_count=$((success_count + 1))
                downloaded=$((downloaded + 1))
                
                # Show occasional progress update
                if [ $((downloaded % 10)) -eq 0 ] || [ "$downloaded" -eq "$total_to_download" ]; then
                    show_progress "$downloaded" "$total_to_download" "Downloading files"
                fi
            else
                fail_count=$((fail_count + 1))
                log_message "--debug" "Failed to download $url ($status)"
            fi
        done < "$results_file"
        
        if [ "$type" = "js" ]; then
            js_downloaded=$success_count
            js_failed=$fail_count
        else
            json_downloaded=$success_count
            json_failed=$fail_count
        fi
    }
    
    if [ "$js_count" -gt 0 ]; then
        log_message "Downloading $js_count JavaScript files with $MAX_THREADS parallel connections..."
        show_progress 0 "$total_to_download" "Downloading files"
        
        cat "${JS_DIR}/js_urls.txt" | 
        xargs -I{} -P "$MAX_THREADS" bash -c "download_file \"{}\" \".js\" \"${JS_DIR}/downloaded\"" > "${TEMP_DIR}/js_download_results.txt"
        
        process_download_results "${TEMP_DIR}/js_download_results.txt" "js"
    fi
    
    if [ "$json_count" -gt 0 ]; then
        log_message "Downloading $json_count JSON files with $MAX_THREADS parallel connections..."
        show_progress "$downloaded" "$total_to_download" "Downloading files"
        
        cat "${JS_DIR}/json_urls.txt" | 
        xargs -I{} -P "$MAX_THREADS" bash -c "download_file \"{}\" \".json\" \"${JS_DIR}/downloaded\"" > "${TEMP_DIR}/json_download_results.txt"
        
        process_download_results "${TEMP_DIR}/json_download_results.txt" "json"
    fi
    
    # Final progress update
    show_progress "$total_to_download" "$total_to_download" "Downloading files"
    
    # Calculate download statistics
    DOWNLOADED_COUNT=$((js_downloaded + json_downloaded))
    local failed_count=$((js_failed + json_failed))
    local download_elapsed
    download_elapsed=$(elapsed_time "$download_start_time")
    
    log_message "Download summary:"
    log_message "- JavaScript: $js_downloaded of $js_count files (${js_failed} failed)"
    log_message "- JSON: $json_downloaded of $json_count files (${json_failed} failed)"
    log_message "- Total: $DOWNLOADED_COUNT of $total_to_download files downloaded in $download_elapsed"
    
    # Create download statistics file
    echo "{
        \"js_total\": $js_count,
        \"js_downloaded\": $js_downloaded,
        \"js_failed\": $js_failed,
        \"json_total\": $json_count,
        \"json_downloaded\": $json_downloaded,
        \"json_failed\": $json_failed,
        \"total_downloaded\": $DOWNLOADED_COUNT,
        \"total_failed\": $failed_count,
        \"download_time\": \"$download_elapsed\"
    }" > "${OUTPUT_DIR}/download_stats.json"
    
    if [ "$DOWNLOADED_COUNT" -eq 0 ]; then
        log_message "--warn" "No files were successfully downloaded"
        return 1
    fi
    
    return 0
}

analyze_files_with_nuclei() {
    if [ "$DOWNLOADED_COUNT" -eq 0 ]; then
        log_message "--warn" "No files to analyze with nuclei"
        return 0
    fi
    
    log_message "Analyzing downloaded files with nuclei..."
    
    # Create list of files to analyze
    local files_list="${TEMP_DIR}/files_to_analyze.txt"
    find "${JS_DIR}/downloaded" -type f \( -name "*.js" -o -name "*.json" \) > "$files_list"
    TOTAL_FILES=$(count_lines "$files_list")
    
    if [ "$TOTAL_FILES" -eq 0 ]; then
        log_message "--warn" "No files found for analysis"
        return 0
    fi
    
    log_message "Analyzing $TOTAL_FILES files with nuclei..."
    local nuclei_start_time
    nuclei_start_time=$(date +%s)
    
    # Prepare nuclei parameters
    local nuclei_params=()
    nuclei_params+=(-l "$files_list")
    nuclei_params+=(-c "$MAX_THREADS")
    nuclei_params+=(-timeout "$SCAN_TIMEOUT")
    nuclei_params+=(-o "${OUTPUT_DIR}/nuclei_results.txt")
    nuclei_params+=(-tags "cve,exposure,misconfiguration,vulnerability,token,api,secrets")
    nuclei_params+=(-severity "low,medium,high,critical")
    nuclei_params+=(-stats)
    nuclei_params+=(-jsonl)
    nuclei_params+=(-silent)
    
    # Add custom templates if specified
    if [ -n "$CUSTOM_NUCLEI_TEMPLATES" ] && [ -d "$CUSTOM_NUCLEI_TEMPLATES" ]; then
        log_message "Using custom nuclei templates from: $CUSTOM_NUCLEI_TEMPLATES"
        nuclei_params+=(-t "$CUSTOM_NUCLEI_TEMPLATES")
    fi
    
    # Run nuclei with monitoring
    $NUCLEI_CMD "${nuclei_params[@]}" > "${OUTPUT_DIR}/nuclei_output.jsonl" 2>"${TEMP_DIR}/nuclei_stderr.log" &
    local nuclei_pid=$!
    
    # Monitor progress
    local processed=0
    while kill -0 $nuclei_pid 2>/dev/null; do
        if [ -f "${OUTPUT_DIR}/nuclei_results.txt" ]; then
            local new_processed
            new_processed=$(count_lines "${OUTPUT_DIR}/nuclei_results.txt")
            
            if [ "$new_processed" -ne "$processed" ]; then
                processed=$new_processed
                show_progress "$processed" "$TOTAL_FILES" "Nuclei analysis" "$(elapsed_time "$nuclei_start_time")"
            fi
        fi
        sleep 2
    done
    
    # Wait for nuclei to finish and get exit status
    wait $nuclei_pid
    local nuclei_status=$?
    local nuclei_elapsed
    nuclei_elapsed=$(elapsed_time "$nuclei_start_time")
    
    # Final progress update
    show_progress "$TOTAL_FILES" "$TOTAL_FILES" "Nuclei analysis" "$nuclei_elapsed"
    
    # Check nuclei exit status
    if [ $nuclei_status -ne 0 ]; then
        log_message "--error" "Nuclei analysis failed (Status: $nuclei_status)"
        if [ -f "${TEMP_DIR}/nuclei_stderr.log" ]; then
            log_message "--debug" "Nuclei error output:"
            cat "${TEMP_DIR}/nuclei_stderr.log" | while read -r line; do
                log_message "--debug" "  $line"
            done
        fi
        return 1
    else
        log_message "${GREEN}Nuclei analysis completed in $nuclei_elapsed${NC}"
    fi
    
    # Process and categorize results
    if [ -f "${OUTPUT_DIR}/nuclei_results.txt" ]; then
        VULN_COUNT=$(count_lines "${OUTPUT_DIR}/nuclei_results.txt")
        
        log_message "Processing and categorizing $VULN_COUNT findings..."
        
        # Categorize by severity
        grep -i "\[critical\]" "${OUTPUT_DIR}/nuclei_results.txt" > "${REPORTS_DIR}/critical_vulns.txt" 2>/dev/null || touch "${REPORTS_DIR}/critical_vulns.txt"
        grep -i "\[high\]" "${OUTPUT_DIR}/nuclei_results.txt" > "${REPORTS_DIR}/high_vulns.txt" 2>/dev/null || touch "${REPORTS_DIR}/high_vulns.txt"
        grep -i "\[medium\]" "${OUTPUT_DIR}/nuclei_results.txt" > "${REPORTS_DIR}/medium_vulns.txt" 2>/dev/null || touch "${REPORTS_DIR}/medium_vulns.txt"
        grep -i "\[low\]" "${OUTPUT_DIR}/nuclei_results.txt" > "${REPORTS_DIR}/low_vulns.txt" 2>/dev/null || touch "${REPORTS_DIR}/low_vulns.txt"
        
        local critical_count
        local high_count
        local medium_count
        local low_count
        critical_count=$(count_lines "${REPORTS_DIR}/critical_vulns.txt")
        high_count=$(count_lines "${REPORTS_DIR}/high_vulns.txt")
        medium_count=$(count_lines "${REPORTS_DIR}/medium_vulns.txt")
        low_count=$(count_lines "${REPORTS_DIR}/low_vulns.txt")
        
        # Save vulnerability statistics
        echo "{
            \"total\": $VULN_COUNT,
            \"critical\": $critical_count,
            \"high\": $high_count,
            \"medium\": $medium_count,
            \"low\": $low_count,
            \"scan_time\": \"$nuclei_elapsed\"
        }" > "${REPORTS_DIR}/vulnerability_stats.json"
        
        log_message "Vulnerability summary:"
        log_message "- Critical: $critical_count"
        log_message "- High: $high_count"
        log_message "- Medium: $medium_count"
        log_message "- Low: $low_count"
        log_message "- Total: $VULN_COUNT"
    else
        log_message "--warn" "No nuclei results file was created"
    fi
    
    return 0
}

analyze_api_endpoints() {
    if [ ! -f "${API_DIR}/all_endpoints.txt" ]; then
        log_message "--warn" "No API endpoints to analyze"
        return 0
    fi
    
    local endpoint_count
    endpoint_count=$(count_lines "${API_DIR}/all_endpoints.txt")
    
    if [ "$endpoint_count" -eq 0 ]; then
        log_message "--warn" "API endpoints file is empty"
        return 0
    fi
    
    log_message "Analyzing $endpoint_count API endpoints..."
    
    # Check if endpoints are alive using httpx
    if command -v httpx &> /dev/null; then
        log_message "Checking which endpoints are active with httpx..."
        local httpx_start
        httpx_start=$(date +%s)
        
        cat "${API_DIR}/all_endpoints.txt" | 
        httpx -silent -threads "$MAX_THREADS" -timeout 10 -status-code -title -tech-detect -follow-redirects -o "${API_DIR}/active_endpoints.txt"
        
        local active_count
        active_count=$(count_lines "${API_DIR}/active_endpoints.txt")
        local httpx_elapsed
        httpx_elapsed=$(elapsed_time "$httpx_start")
        
        log_message "Found $active_count active endpoints in $httpx_elapsed"
        
        # Extract status codes
        local success_count
        local redirect_count
        local error_count
        success_count=$(grep -c "\[2[0-9][0-9]\]" "${API_DIR}/active_endpoints.txt" || echo 0)
        redirect_count=$(grep -c "\[3[0-9][0-9]\]" "${API_DIR}/active_endpoints.txt" || echo 0)
        error_count=$(grep -c "\[4[0-9][0-9]\]" "${API_DIR}/active_endpoints.txt" || echo 0)
        
        log_message "Endpoint status summary:"
        log_message "- Success (2xx): $success_count"
        log_message "- Redirect (3xx): $redirect_count"
        log_message "- Client Error (4xx): $error_count"
        
        # Extract technologies detected
        if grep -q "\[" "${API_DIR}/active_endpoints.txt"; then
            log_message "Technologies detected:"
            grep -o "\[[^]]*\]" "${API_DIR}/active_endpoints.txt" | 
            sort | uniq -c | sort -nr | 
            grep -v "^\s*[0-9]\+\s\+\[[0-9]\+\]" | 
            head -10 | 
            while read -r line; do
                log_message "- $line"
            done
        fi
    else
        log_message "--warn" "httpx not available, skipping API endpoint validation"
        cp "${API_DIR}/all_endpoints.txt" "${API_DIR}/active_endpoints.txt"
    fi
    
    # Analyze endpoints with nuclei if we have active endpoints
    if [ -f "${API_DIR}/active_endpoints.txt" ] && [ "$(count_lines "${API_DIR}/active_endpoints.txt")" -gt 0 ]; then
        log_message "Scanning API endpoints with nuclei..."
        local api_nuclei_start
        api_nuclei_start=$(date +%s)
        
        # Extract urls only if httpx was used (it adds extra info)
        if command -v httpx &> /dev/null; then
            grep -o "https\?://[^ ]*" "${API_DIR}/active_endpoints.txt" > "${API_DIR}/urls_only.txt"
        else
            cp "${API_DIR}/active_endpoints.txt" "${API_DIR}/urls_only.txt"
        fi
        
        # Run nuclei against API endpoints
        $NUCLEI_CMD \
            -l "${API_DIR}/urls_only.txt" \
            -c "$MAX_THREADS" \
            -timeout "$SCAN_TIMEOUT" \
            -tags "cve,exposure,misconfiguration,vulnerability,token,api,secrets" \
            -severity "low,medium,high,critical" \
            -stats \
            -o "${REPORTS_DIR}/api_vulnerabilities.txt" \
            -silent
        
        local api_vuln_count
        api_vuln_count=$(count_lines "${REPORTS_DIR}/api_vulnerabilities.txt")
        local api_nuclei_elapsed
        api_nuclei_elapsed=$(elapsed_time "$api_nuclei_start")
        
        log_message "Found $api_vuln_count potential vulnerabilities in API endpoints in $api_nuclei_elapsed"
        
        if [ "$api_vuln_count" -gt 0 ]; then
            # Categorize API vulnerabilities by severity
            grep -i "\[critical\]" "${REPORTS_DIR}/api_vulnerabilities.txt" > "${REPORTS_DIR}/api_critical_vulns.txt" 2>/dev/null || touch "${REPORTS_DIR}/api_critical_vulns.txt"
            grep -i "\[high\]" "${REPORTS_DIR}/api_vulnerabilities.txt" > "${REPORTS_DIR}/api_high_vulns.txt" 2>/dev/null || touch "${REPORTS_DIR}/api_high_vulns.txt"
            grep -i "\[medium\]" "${REPORTS_DIR}/api_vulnerabilities.txt" > "${REPORTS_DIR}/api_medium_vulns.txt" 2>/dev/null || touch "${REPORTS_DIR}/api_medium_vulns.txt"
            grep -i "\[low\]" "${REPORTS_DIR}/api_vulnerabilities.txt" > "${REPORTS_DIR}/api_low_vulns.txt" 2>/dev/null || touch "${REPORTS_DIR}/api_low_vulns.txt"
            
            local api_critical_count
            local api_high_count
            local api_medium_count
            local api_low_count
            api_critical_count=$(count_lines "${REPORTS_DIR}/api_critical_vulns.txt")
            api_high_count=$(count_lines "${REPORTS_DIR}/api_high_vulns.txt")
            api_medium_count=$(count_lines "${REPORTS_DIR}/api_medium_vulns.txt")
            api_low_count=$(count_lines "${REPORTS_DIR}/api_low_vulns.txt")
            
            log_message "API vulnerability summary:"
            log_message "- Critical: $api_critical_count"
            log_message "- High: $api_high_count"
            log_message "- Medium: $api_medium_count"
            log_message "- Low: $api_low_count"
            
            # Save API vulnerability statistics
            echo "{
                \"total\": $api_vuln_count,
                \"critical\": $api_critical_count,
                \"high\": $api_high_count,
                \"medium\": $api_medium_count,
                \"low\": $api_low_count,
                \"scan_time\": \"$api_nuclei_elapsed\"
            }" > "${REPORTS_DIR}/api_vulnerability_stats.json"
            
            # Add to total vulnerability count
            VULN_COUNT=$((VULN_COUNT + api_vuln_count))
        fi
    else
        log_message "--warn" "No active API endpoints found for scanning"
    fi
    
    # Parameter fuzzing with ffuf if available
    if command -v ffuf &> /dev/null && [ -f "${API_DIR}/param_urls.txt" ] && [ "$(count_lines "${API_DIR}/param_urls.txt")" -gt 0 ]; then
        log_message "Performing basic parameter fuzzing with ffuf..."
        mkdir -p "${REPORTS_DIR}/ffuf_results"
        
        # Create a small wordlist of common attack patterns
        cat > "${TEMP_DIR}/attack_patterns.txt" << EOL
'
"
<script>alert(1)</script>
1' OR '1'='1
1 OR 1=1
../../../../../../etc/passwd
/etc/passwd
EOL
        
        # Take a sample of parameterized URLs for testing
        head -20 "${API_DIR}/param_urls.txt" > "${TEMP_DIR}/param_sample.txt"
        
        # Log sample size
        local sample_size
        sample_size=$(count_lines "${TEMP_DIR}/param_sample.txt")
        log_message "Testing a sample of $sample_size parameterized URLs"
        
        # Process each URL
        while IFS= read -r url; do
            # Extract parameters
            local params
            params=$(echo "$url" | grep -o '\?[^[:space:]]*' | sed 's/?//' | tr '&' '\n' | cut -d= -f1)
            
            if [ -n "$params" ]; then
                # Create URL with FUZZ placeholder for each parameter
                while IFS= read -r param; do
                    [ -z "$param" ] && continue
                    
                    local fuzz_url
                    fuzz_url=$(echo "$url" | sed "s/\($param=\)[^&]*/\1FUZZ/g")
                    local safe_param
                    safe_param=$(echo "$param" | tr -cd '[:alnum:]._-')
                    
                    log_message "--debug" "Fuzzing parameter $param in $fuzz_url"
                    
                    # Run ffuf
                    ffuf -u "$fuzz_url" -w "${TEMP_DIR}/attack_patterns.txt" -mc all -fr "Internal Server Error" -o "${REPORTS_DIR}/ffuf_results/${safe_param}_result.json" -of json -timeout 5 -t 2 -s
                done <<< "$params"
            fi
        done < "${TEMP_DIR}/param_sample.txt"
        
        # Analyze ffuf results
        log_message "Analyzing parameter fuzzing results..."
        local interesting_results=0
        
        find "${REPORTS_DIR}/ffuf_results" -name "*_result.json" -type f | while read -r result_file; do
            if [ -s "$result_file" ]; then
                # Check if there are any interesting responses
                local has_500
                has_500=$(jq '.results[] | select(.status == 500)' "$result_file" 2>/dev/null)
                local has_error_message
                has_error_message=$(jq '.results[] | select(.response | contains("error") or contains("exception") or contains("stack trace"))' "$result_file" 2>/dev/null)
                
                if [ -n "$has_500" ] || [ -n "$has_error_message" ]; then
                    interesting_results=$((interesting_results + 1))
                    log_message "--warn" "Potential vulnerability found in $(basename "$result_file" _result.json) parameter"
                    jq -r '.results[] | "  - Pattern: \(.input.FUZZ), Status: \(.status)"' "$result_file" 2>/dev/null | head -5 | while read -r line; do
                        log_message "$line"
                    done
                fi
            fi
        done
        
        if [ "$interesting_results" -gt 0 ]; then
            log_message "${YELLOW}Found $interesting_results potentially vulnerable parameters${NC}"
        else
            log_message "No obvious parameter vulnerabilities found in the tested sample"
        fi
    fi
    
    return 0
}

generate_reports() {
    log_message "Generating final reports..."
    
    # Generate JSON summary
    cat > "${REPORTS_DIR}/scan_summary.json" << EOL
{
    "scan_id": "$SCAN_ID",
    "target": "$TARGET_URL",
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "duration": "$(elapsed_time "$START_TIME")",
    "stats": {
        "total_urls": $TOTAL_LINKS,
        "js_files": $(count_lines "${JS_DIR}/js_urls.txt" 2>/dev/null || echo 0),
        "json_files": $(count_lines "${JS_DIR}/json_urls.txt" 2>/dev/null || echo 0),
        "api_endpoints": $(count_lines "${API_DIR}/all_endpoints.txt" 2>/dev/null || echo 0),
        "downloaded_files": $DOWNLOADED_COUNT,
        "analyzed_files": $TOTAL_FILES,
        "vulnerabilities": {
            "total": $VULN_COUNT,
            "critical": $(count_lines "${REPORTS_DIR}/critical_vulns.txt" 2>/dev/null || echo 0) + $(count_lines "${REPORTS_DIR}/api_critical_vulns.txt" 2>/dev/null || echo 0),
            "high": $(count_lines "${REPORTS_DIR}/high_vulns.txt" 2>/dev/null || echo 0) + $(count_lines "${REPORTS_DIR}/api_high_vulns.txt" 2>/dev/null || echo 0),
            "medium": $(count_lines "${REPORTS_DIR}/medium_vulns.txt" 2>/dev/null || echo 0) + $(count_lines "${REPORTS_DIR}/api_medium_vulns.txt" 2>/dev/null || echo 0),
            "low": $(count_lines "${REPORTS_DIR}/low_vulns.txt" 2>/dev/null || echo 0) + $(count_lines "${REPORTS_DIR}/api_low_vulns.txt" 2>/dev/null || echo 0)
        }
    }
}
EOL

    # Generate HTML Report
    local current_date
    current_date=$(date '+%Y-%m-%d %H:%M:%S')
    local scan_duration
    scan_duration=$(elapsed_time "$START_TIME")
    
    # Calculate vulnerability counts
    local critical_count
    local high_count
    local medium_count
    local low_count
    critical_count=$(($(count_lines "${REPORTS_DIR}/critical_vulns.txt" 2>/dev/null || echo 0) + $(count_lines "${REPORTS_DIR}/api_critical_vulns.txt" 2>/dev/null || echo 0)))
    high_count=$(($(count_lines "${REPORTS_DIR}/high_vulns.txt" 2>/dev/null || echo 0) + $(count_lines "${REPORTS_DIR}/api_high_vulns.txt" 2>/dev/null || echo 0)))
    medium_count=$(($(count_lines "${REPORTS_DIR}/medium_vulns.txt" 2>/dev/null || echo 0) + $(count_lines "${REPORTS_DIR}/api_medium_vulns.txt" 2>/dev/null || echo 0)))
    low_count=$(($(count_lines "${REPORTS_DIR}/low_vulns.txt" 2>/dev/null || echo 0) + $(count_lines "${REPORTS_DIR}/api_low_vulns.txt" 2>/dev/null || echo 0)))
    
    cat > "${REPORTS_DIR}/report.html" << EOL
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report: ${TARGET_NAME}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        header h1 {
            margin: 0;
            font-size: 24px;
        }
        header p {
            margin: 5px 0 0;
            font-size: 14px;
            opacity: 0.8;
        }
        .summary-card {
            background-color: white;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }
        .vuln-summary {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-top: 15px;
        }
        .vuln-box {
            flex: 1;
            min-width: 120px;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            color: white;
            font-weight: bold;
        }
        .critical {
            background-color: #e74c3c;
        }
        .high {
            background-color: #e67e22;
        }
        .medium {
            background-color: #f1c40f;
            color: #333;
        }
        .low {
            background-color: #2ecc71;
        }
        .total {
            background-color: #3498db;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .stat-item {
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
        }
        .stat-label {
            margin-top: 5px;
            font-size: 14px;
            color: #7f8c8d;
        }
        .section {
            margin-top: 30px;
        }
        h2 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            text-align: left;
            padding: 12px 15px;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            font-weight: bold;
            color: #2c3e50;
        }
        tr:hover {
            background-color: #f8f9fa;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            font-size: 14px;
            color: #7f8c8d;
        }
        .severity-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 12px;
            text-transform: uppercase;
        }
        .collapsible {
            background-color: #f8f9fa;
            color: #2c3e50;
            cursor: pointer;
            padding: 18px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 16px;
            font-weight: bold;
            border-radius: 5px;
            margin-top: 10px;
        }
        .active, .collapsible:hover {
            background-color: #e9ecef;
        }
        .collapsible:after {
            content: '\\002B';
            color: #3498db;
            font-weight: bold;
            float: right;
            margin-left: 5px;
        }
        .active:after {
            content: "\\2212";
        }
        .content {
            padding: 0 18px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.2s ease-out;
            background-color: white;
            border-radius: 0 0 5px 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Web Security Scan Report</h1>
            <p>Generated on: ${current_date} | Scan ID: ${SCAN_ID}</p>
        </header>
        
        <div class="summary-card">
            <h2>Executive Summary</h2>
            <p><strong>Target:</strong> ${TARGET_URL}</p>
            <p><strong>Scan Duration:</strong> ${scan_duration}</p>
            
            <div class="vuln-summary">
                <div class="vuln-box critical">
                    <div style="font-size: 24px;">${critical_count}</div>
                    <div>Critical</div>
                </div>
                <div class="vuln-box high">
                    <div style="font-size: 24px;">${high_count}</div>
                    <div>High</div>
                </div>
                <div class="vuln-box medium">
                    <div style="font-size: 24px;">${medium_count}</div>
                    <div>Medium</div>
                </div>
                <div class="vuln-box low">
                    <div style="font-size: 24px;">${low_count}</div>
                    <div>Low</div>
                </div>
                <div class="vuln-box total">
                    <div style="font-size: 24px;">${VULN_COUNT}</div>
                    <div>Total</div>
                </div>
            </div>
            
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-value">${TOTAL_LINKS}</div>
                    <div class="stat-label">Discovered URLs</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">$(count_lines "${JS_DIR}/js_urls.txt" 2>/dev/null || echo 0)</div>
                    <div class="stat-label">JavaScript Files</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">$(count_lines "${API_DIR}/all_endpoints.txt" 2>/dev/null || echo 0)</div>
                    <div class="stat-label">API Endpoints</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${DOWNLOADED_COUNT}</div>
                    <div class="stat-label">Files Analyzed</div>
                </div>
            </div>
        </div>
EOL

    # Function to add vulnerabilities section
    add_vuln_section() {
        local severity="$1"
        local title="$2"
        local file="$3"
        local count
        count=$(count_lines "$file" 2>/dev/null || echo 0)
        
        if [ "$count" -gt 0 ]; then
            cat >> "${REPORTS_DIR}/report.html" << EOL
        <button class="collapsible">${title} (${count})</button>
        <div class="content">
            <table>
                <tr>
                    <th>Vulnerability</th>
                    <th>URL</th>
                </tr>
EOL
            
            # Add rows
            while IFS= read -r line; do
                local vuln_description
                local vuln_url
                vuln_description=$(echo "$line" | sed -E "s/\[$severity\][[:space:]]+([^[]+).*/\1/" | sed 's/[<>]/\\&/g')
                vuln_url=$(echo "$line" | grep -o 'http[s]\?://[^ ]*' | head -1 | sed 's/[<>]/\\&/g')
                
                cat >> "${REPORTS_DIR}/report.html" << EOL
                <tr>
                    <td>${vuln_description}</td>
                    <td><a href="${vuln_url}" target="_blank">${vuln_url}</a></td>
                </tr>
EOL
            done < "$file"
            
            cat >> "${REPORTS_DIR}/report.html" << EOL
            </table>
        </div>
EOL
        fi
    }

    # Add vulnerability sections if they exist
    cat >> "${REPORTS_DIR}/report.html" << EOL
        <div class="section">
            <h2>Vulnerability Details</h2>
EOL

    # Add findings by severity
    if [ -f "${REPORTS_DIR}/critical_vulns.txt" ] || [ -f "${REPORTS_DIR}/api_critical_vulns.txt" ]; then
        # Combine both files if they exist
        if [ -f "${REPORTS_DIR}/critical_vulns.txt" ] && [ -f "${REPORTS_DIR}/api_critical_vulns.txt" ]; then
            cat "${REPORTS_DIR}/critical_vulns.txt" "${REPORTS_DIR}/api_critical_vulns.txt" > "${TEMP_DIR}/all_critical.txt"
            add_vuln_section "critical" "Critical Vulnerabilities" "${TEMP_DIR}/all_critical.txt"
        elif [ -f "${REPORTS_DIR}/critical_vulns.txt" ]; then
            add_vuln_section "critical" "Critical Vulnerabilities" "${REPORTS_DIR}/critical_vulns.txt"
        else
            add_vuln_section "critical" "Critical Vulnerabilities" "${REPORTS_DIR}/api_critical_vulns.txt"
        fi
    fi
    
    if [ -f "${REPORTS_DIR}/high_vulns.txt" ] || [ -f "${REPORTS_DIR}/api_high_vulns.txt" ]; then
        # Combine both files if they exist
        if [ -f "${REPORTS_DIR}/high_vulns.txt" ] && [ -f "${REPORTS_DIR}/api_high_vulns.txt" ]; then
            cat "${REPORTS_DIR}/high_vulns.txt" "${REPORTS_DIR}/api_high_vulns.txt" > "${TEMP_DIR}/all_high.txt"
            add_vuln_section "high" "High Vulnerabilities" "${TEMP_DIR}/all_high.txt"
        elif [ -f "${REPORTS_DIR}/high_vulns.txt" ]; then
            add_vuln_section "high" "High Vulnerabilities" "${REPORTS_DIR}/high_vulns.txt"
        else
            add_vuln_section "high" "High Vulnerabilities" "${REPORTS_DIR}/api_high_vulns.txt"
        fi
    fi
    
    if [ -f "${REPORTS_DIR}/medium_vulns.txt" ] || [ -f "${REPORTS_DIR}/api_medium_vulns.txt" ]; then
        # Combine both files if they exist
        if [ -f "${REPORTS_DIR}/medium_vulns.txt" ] && [ -f "${REPORTS_DIR}/api_medium_vulns.txt" ]; then
            cat "${REPORTS_DIR}/medium_vulns.txt" "${REPORTS_DIR}/api_medium_vulns.txt" > "${TEMP_DIR}/all_medium.txt"
            add_vuln_section "medium" "Medium Vulnerabilities" "${TEMP_DIR}/all_medium.txt"
        elif [ -f "${REPORTS_DIR}/medium_vulns.txt" ]; then
            add_vuln_section "medium" "Medium Vulnerabilities" "${REPORTS_DIR}/medium_vulns.txt"
        else
            add_vuln_section "medium" "Medium Vulnerabilities" "${REPORTS_DIR}/api_medium_vulns.txt"
        fi
    fi
    
    if [ -f "${REPORTS_DIR}/low_vulns.txt" ] || [ -f "${REPORTS_DIR}/api_low_vulns.txt" ]; then
        # Combine both files if they exist
        if [ -f "${REPORTS_DIR}/low_vulns.txt" ] && [ -f "${REPORTS_DIR}/api_low_vulns.txt" ]; then
            cat "${REPORTS_DIR}/low_vulns.txt" "${REPORTS_DIR}/api_low_vulns.txt" > "${TEMP_DIR}/all_low.txt"
            add_vuln_section "low" "Low Vulnerabilities" "${TEMP_DIR}/all_low.txt"
        elif [ -f "${REPORTS_DIR}/low_vulns.txt" ]; then
            add_vuln_section "low" "Low Vulnerabilities" "${REPORTS_DIR}/low_vulns.txt"
        else
            add_vuln_section "low" "Low Vulnerabilities" "${REPORTS_DIR}/api_low_vulns.txt"
        fi
    fi

    # Complete the report
    cat >> "${REPORTS_DIR}/report.html" << EOL
        </div>
        
        <div class="section">
            <h2>Scan Details</h2>
            <div class="summary-card">
                <p><strong>Scan Command:</strong> Enhanced Web Security Scanner v${VERSION}</p>
                <p><strong>Configuration:</strong> Max threads: ${MAX_THREADS}, Crawl depth: ${CRAWL_DEPTH}, Scan timeout: ${SCAN_TIMEOUT}s</p>
                <p><strong>Target:</strong> ${TARGET_URL}</p>
                <p><strong>Output Directory:</strong> ${OUTPUT_DIR}</p>
                <p><strong>Report Files:</strong> ${REPORTS_DIR}/report.html, ${REPORTS_DIR}/scan_summary.json</p>
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by Enhanced Web Security Scanner v${VERSION} on ${current_date}</p>
            <p>Scan ID: ${SCAN_ID}</p>
        </div>
    </div>
    
    <script>
    var coll = document.getElementsByClassName("collapsible");
    var i;

    for (i = 0; i < coll.length; i++) {
        coll[i].addEventListener("click", function() {
            this.classList.toggle("active");
            var content = this.nextElementSibling;
            if (content.style.maxHeight){
                content.style.maxHeight = null;
            } else {
                content.style.maxHeight = content.scrollHeight + "px";
            }
        });
    }
    </script>
</body>
</html>
EOL

    log_message "${GREEN}Generated HTML report at ${REPORTS_DIR}/report.html${NC}"
    log_message "${GREEN}Generated JSON summary at ${REPORTS_DIR}/scan_summary.json${NC}"
    
    # Update scan state to completed
    echo "{\"scan_id\":\"$SCAN_ID\",\"target\":\"$TARGET_URL\",\"start_time\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\",\"end_time\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\",\"status\":\"completed\"}" > "${OUTPUT_DIR}/scan_state.json"
    
    return 0
}

# ================ MAIN FUNCTION ================
main() {
    # Display banner
    show_banner
    
    # Check dependencies
    check_dependencies
    
    # Load configuration
    load_config
    
    # Get target URL
    if [ $# -ge 1 ]; then
        TARGET_URL="$1"
    else
        echo -e "${YELLOW}Enter target URL:${NC}"
        read -r TARGET_URL
    fi
    
    # Validate URL
    validate_url "$TARGET_URL" || exit 1
    
    # Extract target name for directory naming
    TARGET_NAME=$(echo "$TARGET_URL" | sed -e 's/https\?:\/\///' -e 's/\/.*$//' -e 's/:[0-9]\+$//')
    
    # Setup directories
    setup_directories "$TARGET_NAME"
    
    # Echo configuration settings
    log_message "Configuration settings:"
    log_message "- Threads: ${MAX_THREADS}"
    log_message "- Crawl depth: ${CRAWL_DEPTH}"
    log_message "- Scan timeout: ${SCAN_TIMEOUT}s"
    log_message "- Download timeout: ${DOWNLOAD_TIMEOUT}s"
    log_message "- Target URL: ${TARGET_URL}"
    
    # Progress tracking
    SCAN_PROGRESS="crawling"
    
    # Crawl target
    log_message "Starting scan of ${TARGET_URL}..."
    crawl_target "$TARGET_URL" || {
        log_message "--error" "Crawling failed. Exiting."
        exit 1
    }
    
    # Extract endpoints
    SCAN_PROGRESS="extracting"
    extract_endpoints "${OUTPUT_DIR}/crawl_results.txt" || {
        log_message "--warn" "Endpoint extraction produced no results"
    }
    
    # Download files
    SCAN_PROGRESS="downloading"
    download_files || {
        log_message "--warn" "No files were successfully downloaded"
    }
    
    # Analyze files with nuclei
    SCAN_PROGRESS="analyzing_files"
    analyze_files_with_nuclei
    
    # Analyze API endpoints
    SCAN_PROGRESS="analyzing_api"
    analyze_api_endpoints
    
    # Generate reports
    SCAN_PROGRESS="reporting"
    generate_reports
    
    # Display summary
    log_message "${BLUE}======== Scan Summary ========${NC}"
    log_message "Target: ${TARGET_URL}"
    log_message "Total URLs discovered: ${TOTAL_LINKS}"
    log_message "Files downloaded and analyzed: ${DOWNLOADED_COUNT}"
    
    if [ "$VULN_COUNT" -gt 0 ]; then
        local critical_count
        local high_count
        local medium_count
        local low_count
        critical_count=$(($(count_lines "${REPORTS_DIR}/critical_vulns.txt" 2>/dev/null || echo 0) + $(count_lines "${REPORTS_DIR}/api_critical_vulns.txt" 2>/dev/null || echo 0)))
        high_count=$(($(count_lines "${REPORTS_DIR}/high_vulns.txt" 2>/dev/null || echo 0) + $(count_lines "${REPORTS_DIR}/api_high_vulns.txt" 2>/dev/null || echo 0)))
        medium_count=$(($(count_lines "${REPORTS_DIR}/medium_vulns.txt" 2>/dev/null || echo 0) + $(count_lines "${REPORTS_DIR}/api_medium_vulns.txt" 2>/dev/null || echo 0)))
        low_count=$(($(count_lines "${REPORTS_DIR}/low_vulns.txt" 2>/dev/null || echo 0) + $(count_lines "${REPORTS_DIR}/api_low_vulns.txt" 2>/dev/null || echo 0)))
        
        log_message "${RED}Found $VULN_COUNT potential vulnerabilities:${NC}"
        [ "$critical_count" -gt 0 ] && log_message "${RED}- Critical: $critical_count${NC}"
        [ "$high_count" -gt 0 ] && log_message "${RED}- High: $high_count${NC}"
        [ "$medium_count" -gt 0 ] && log_message "${YELLOW}- Medium: $medium_count${NC}"
        [ "$low_count" -gt 0 ] && log_message "${GREEN}- Low: $low_count${NC}"
    else
        log_message "${GREEN}No vulnerabilities found${NC}"
    fi
    
    log_message "Scan duration: $(elapsed_time "$START_TIME")"
    log_message "Results saved to: ${OUTPUT_DIR}"
    log_message "HTML Report: ${REPORTS_DIR}/report.html"
    
    return 0
}

# ================ SCRIPT EXECUTION ================
# Execute main function with all arguments
main "$@"
