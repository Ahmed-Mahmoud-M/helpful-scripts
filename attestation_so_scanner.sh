#!/bin/bash

# Directory to scan
TARGET_DIR="$1"
OUTPUT_FILE="attestation_so_report.txt"

# Keywords to search for in .so files
KEYWORDS=("attest" "safetynet" "nonce" "integrity" "verify" "playintegrity" "cert" "devicecheck" "signature")


if [[ -z "$TARGET_DIR" ]]; then
    echo "Usage: $0 <directory>"
    exit 1
fi


echo "Attestation .so Scanner Report" > "$OUTPUT_FILE"
echo "Target Directory: $TARGET_DIR" >> "$OUTPUT_FILE"
echo "Scan Date: $(date)" >> "$OUTPUT_FILE"
echo "=======================================" >> "$OUTPUT_FILE"

# Find all .so files
SO_FILES=$(find "$TARGET_DIR" -type f -name "*.so")

for FILE in $SO_FILES; do
    echo -e "\nAnalyzing: $FILE" >> "$OUTPUT_FILE"
    echo "---------------------------------------" >> "$OUTPUT_FILE"

    # STRINGS check
    echo ">> Strings match:" >> "$OUTPUT_FILE"
    for keyword in "${KEYWORDS[@]}"; do
        STR_MATCH=$(strings "$FILE" | grep -i "$keyword")
        if [[ ! -z "$STR_MATCH" ]]; then
            echo "  [*] Found \"$keyword\":" >> "$OUTPUT_FILE"
            echo "$STR_MATCH" | sed 's/^/    /' >> "$OUTPUT_FILE"
        fi
    done

    # NM check
    echo ">> Exported symbols (nm):" >> "$OUTPUT_FILE"
    nm -D --defined-only "$FILE" 2>/dev/null | grep -Ei 'attest|token|verify|check' | sed 's/^/    /' >> "$OUTPUT_FILE"

    # Readelf
    echo ">> Readelf function symbols:" >> "$OUTPUT_FILE"
    readelf -s "$FILE" 2>/dev/null | grep -Ei 'attest|token|verify|check' | sed 's/^/    /' >> "$OUTPUT_FILE"

    echo "---------------------------------------" >> "$OUTPUT_FILE"
done

echo -e "\nScan complete. Results saved in: $OUTPUT_FILE"
