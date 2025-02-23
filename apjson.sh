#!/bin/bash
set -eo pipefail

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
MAX_THREADS=1
TIMEOUT=600

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_message() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[$timestamp] $1" | tee -a "${LOG_FILE}"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 is not installed${NC}"
        exit 1
    fi
}

validate_url() {
    if [[ ! "$1" =~ ^https?:// ]]; then
        echo -e "${RED}Error: Invalid URL format. Use http:// or https://${NC}"
        exit 1
    fi
}

echo "Checking dependencies..."
for cmd in $(go env GOPATH)/bin/katana nuclei curl awk; do
    check_command "$cmd"
done

echo -e "${YELLOW}Enter target URL:${NC}"
read -r url
validate_url "$url"

TARGET_NAME=$(echo "$url" | sed -e 's/https\?:\/\///' -e 's/\/.*$//' -e 's/\..*com//')
OUTPUT_DIR="./${TARGET_NAME}_${TIMESTAMP}"
JS_DIR="${OUTPUT_DIR}/js_files"
LOG_FILE="${OUTPUT_DIR}/scan_${TIMESTAMP}.log"

mkdir -p "$JS_DIR" || { echo -e "${RED}Error: Failed to create directory${NC}"; exit 1; }
log_message "Creating output directory: ${OUTPUT_DIR}"

log_message "${GREEN}Extracting links from ${url} using katana...${NC}"
$(go env GOPATH)/bin/katana \
    -u "$url" \
    -c 10 \
    -d 3 \
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
    -silent \
    -v \
    2>&1 | tee "${OUTPUT_DIR}/katana_output.txt"
if [ ${PIPESTATUS[0]} -ne 0 ]; then
    log_message "${RED}Error: katana failed${NC}"
    log_message "Error details:"
    cat "${OUTPUT_DIR}/katana_output.txt" | while read -r line; do log_message "  $line"; done
    exit 1
fi

log_message "Filtering JavaScript, JSON, and API files..."
JS_COUNT=0
JSON_COUNT=0
API_COUNT=0

if [ -s "${OUTPUT_DIR}/katana_output.txt" ]; then
    # Create files only if there are matches
    JS_LINKS=$(awk '/\.js($|\?)/ {for(i=1;i<=NF;i++) if($i~/^https/) print $i}' "${OUTPUT_DIR}/katana_output.txt" | grep -v '^$')
    [ -n "$JS_LINKS" ] && echo "$JS_LINKS" > "${JS_DIR}/js_urls.txt" && JS_COUNT=$(wc -l < "${JS_DIR}/js_urls.txt") || JS_COUNT=0
    JSON_LINKS=$(awk '/\.json($|\?)/ {for(i=1;i<=NF;i++) if($i~/^https/) print $i}' "${OUTPUT_DIR}/katana_output.txt" | grep -v '^$')
    [ -n "$JSON_LINKS" ] && echo "$JSON_LINKS" > "${JS_DIR}/json_urls.txt" && JSON_COUNT=$(wc -l < "${JS_DIR}/json_urls.txt") || JSON_COUNT=0
    API_LINKS=$(awk '/(\/api\/|\/v[0-9]\/|\/endpoint\/)/ {for(i=1;i<=NF;i++) if($i~/^https/) print $i}' "${OUTPUT_DIR}/katana_output.txt" | grep -v '^$')
    [ -n "$API_LINKS" ] && echo "$API_LINKS" > "${JS_DIR}/api_urls.txt" && API_COUNT=$(wc -l < "${JS_DIR}/api_urls.txt") || API_COUNT=0
else
    log_message "${YELLOW}Warning: katana_output.txt is empty or not found${NC}"
fi

log_message "JavaScript files: ${JS_COUNT}"
log_message "JSON files: ${JSON_COUNT}"
log_message "API links: ${API_COUNT}"

[ "$JS_COUNT" -eq 0 ] && [ "$JSON_COUNT" -eq 0 ] && [ "$API_COUNT" -eq 0 ] && {
    log_message "${YELLOW}Warning: No files or APIs found${NC}"
    exit 0
}

# Show extracted links only if files were created
[ "$JS_COUNT" -gt 0 ] && log_message "Extracted JavaScript links:" && cat "${JS_DIR}/js_urls.txt" | while read -r line; do log_message "  $line"; done
[ "$JSON_COUNT" -gt 0 ] && log_message "Extracted JSON links:" && cat "${JS_DIR}/json_urls.txt" | while read -r line; do log_message "  $line"; done
[ "$API_COUNT" -gt 0 ] && log_message "Extracted API links:" && cat "${JS_DIR}/api_urls.txt" | while read -r line; do log_message "  $line"; done

# Download only if there are JS or JSON files
if [ "$JS_COUNT" -gt 0 ] || [ "$JSON_COUNT" -gt 0 ]; then
    log_message "Downloading JavaScript and JSON files..."
    mkdir -p "${JS_DIR}/downloaded"
    [ "$JS_COUNT" -gt 0 ] && while read -r js_url; do
        [ -n "$js_url" ] && { 
            log_message "Attempting to download: $js_url"
            curl -s -L -o "${JS_DIR}/downloaded/$(echo "$js_url" | md5sum | cut -c 1-32).js" "$js_url" && log_message "${GREEN}Downloaded $js_url${NC}" || log_message "${RED}Error: Failed to download $js_url${NC}"
        }
    done < "${JS_DIR}/js_urls.txt"
    [ "$JSON_COUNT" -gt 0 ] && while read -r json_url; do
        [ -n "$json_url" ] && { 
            log_message "Attempting to download: $json_url"
            curl -s -L -o "${JS_DIR}/downloaded/$(echo "$json_url" | md5sum | cut -c 1-32).json" "$json_url" && log_message "${GREEN}Downloaded $json_url${NC}" || log_message "${RED}Error: Failed to download $json_url${NC}"
        }
    done < "${JS_DIR}/json_urls.txt"
    DOWNLOADED_COUNT=$(find "${JS_DIR}/downloaded" -type f | wc -l)
    log_message "Successfully downloaded ${DOWNLOADED_COUNT} files"
    [ "$DOWNLOADED_COUNT" -gt 0 ] && log_message "Downloaded files:" && find "${JS_DIR}/downloaded" -type f | while read -r file; do log_message "  $file"; done
else
    log_message "${YELLOW}Warning: No JavaScript or JSON files to download${NC}"
    DOWNLOADED_COUNT=0
fi

# Analyze with nuclei only if files were downloaded
if [ "$DOWNLOADED_COUNT" -gt 0 ]; then
    log_message "Analyzing files with nuclei..."
    JS_FILES_LIST="${OUTPUT_DIR}/js_files.txt"
    find "${JS_DIR}/downloaded" -type f \( -name "*.js" -o -name "*.json" \) | head -n 10 > "$JS_FILES_LIST" 2>/dev/null || echo "" > "$JS_FILES_LIST"
    TOTAL_FILES=$(wc -l < "$JS_FILES_LIST")
    if [ "$TOTAL_FILES" -gt 0 ]; then
        echo -ne "Nuclei analysis in progress: [0%] \r"
        nuclei \
            -l "$JS_FILES_LIST" \
            -c 10 \
            -timeout "$TIMEOUT" \
            -o "${OUTPUT_DIR}/nuclei_results.txt" \
            -tags cve,exposure \
            -stats \
            -si 5 \
            -jsonl \
            > "${OUTPUT_DIR}/nuclei_output.jsonl" 2>>"${LOG_FILE}" &
        NUCLEI_PID=$!
        while kill -0 $NUCLEI_PID 2>/dev/null; do
            if [ -s "${OUTPUT_DIR}/nuclei_output.jsonl" ]; then
                PROCESSED=$(wc -l < "${OUTPUT_DIR}/nuclei_output.jsonl")
                PERCENT=$(( (PROCESSED * 100) / TOTAL_FILES ))
                echo -ne "Nuclei analysis in progress: [${PERCENT}%] \r"
            fi
            sleep 1
        done
        wait $NUCLEI_PID
        if [ $? -ne 0 ]; then
            log_message "${RED}Error: nuclei failed${NC}"
            exit 1
        fi
        echo -e "Nuclei analysis in progress: [100%]"
    else
        log_message "${YELLOW}Warning: No files available for analysis${NC}"
    fi
else
    log_message "${YELLOW}Warning: Skipping nuclei analysis due to no downloaded files${NC}"
fi

log_message "Generating summary..."
VULN_COUNT=$( [ -f "${OUTPUT_DIR}/nuclei_results.txt" ] && wc -l < "${OUTPUT_DIR}/nuclei_results.txt" 2>/dev/null || echo 0 )
[ "$VULN_COUNT" -gt 0 ] && log_message "${RED}Potential vulnerabilities: ${VULN_COUNT}${NC}" || log_message "${GREEN}No potential vulnerabilities found${NC}"

[ "$VULN_COUNT" -gt 0 ] && {
    log_message "Sample of results:"
    head -n 5 "${OUTPUT_DIR}/nuclei_results.txt" | while read -r line; do log_message "${RED}  $line${NC}"; done
}

[ "$JS_COUNT" -gt 0 ] && log_message "${GREEN}Extracted ${JS_COUNT} JavaScript files${NC}"
[ "$JSON_COUNT" -gt 0 ] && log_message "${GREEN}Extracted ${JSON_COUNT} JSON files${NC}"
[ "$API_COUNT" -gt 0 ] && log_message "${GREEN}Extracted ${API_COUNT} API links${NC}"

# Clean up only files that exist
for file in "${JS_DIR}/js_urls.txt" "${JS_DIR}/json_urls.txt" "${JS_DIR}/api_urls.txt"; do
    [ -f "$file" ] && rm -f "$file"
done

log_message "${BLUE}Scan completed successfully!${NC}"
log_message "Results saved in: ${OUTPUT_DIR}"
log_message "Log file: ${LOG_FILE}"
