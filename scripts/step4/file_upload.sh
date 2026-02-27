#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step4_file_upload"

check_file_upload() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    local upload_paths=("/upload" "/uploads" "/wp-content/uploads" "/media/upload" "/api/upload" "/files/upload" "/file-upload" "/attachment" "/assets/upload" "/images/upload")
    local issues=()
    local severity="INFO"

    for path in "${upload_paths[@]}"; do
        local url="${base_url}${path}"
        local http_code
        http_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null || echo "000")

        if [[ "$http_code" == "200" ]]; then
            # Check if it accepts POST (upload form exists)
            local page
            page=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null || echo "")
            if echo "$page" | grep -qi "upload\|file.*input\|enctype.*multipart\|choose.*file\|drag.*drop"; then
                issues+=("Upload endpoint accessible at $path (HTTP $http_code)")
                severity="HIGH"
            fi
        fi

        # Test with a crafted PHP file upload (no actual payload — just MIME probe)
        if [[ "$http_code" == "200" ]] || [[ "$http_code" == "405" ]]; then
            local upload_response
            upload_response=$(curl -sS -X POST \
                --max-time "${TIMEOUT:-10}" \
                -F "file=@/dev/null;filename=test.php;type=application/x-php" \
                -F "upload=1" \
                "$url" 2>/dev/null || echo "")

            # Check if server accepted the PHP file (danger signal)
            if echo "$upload_response" | grep -qiE "success|uploaded|saved|url.*\.php|location.*\.php"; then
                issues+=("Server may accept PHP file uploads at $path — CRITICAL risk")
                severity="CRITICAL"
            fi
        fi
    done

    if [[ ${#issues[@]} -eq 0 ]]; then
        echo "PASS|No unrestricted upload endpoints found at common paths|File uploads restricted to allowed types only|INFO|"
        return
    fi

    local issues_str
    issues_str=$(IFS="; "; printf '%s' "${issues[*]}")

    if [[ "$severity" == "CRITICAL" ]]; then
        echo "FAIL|$issues_str|Block executable file uploads; whitelist allowed types; store outside web root|CRITICAL|SEC-UPLOAD-002"
    else
        echo "WARN|$issues_str|Validate file types; restrict uploads; scan uploaded files|$severity|SEC-UPLOAD-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking file upload endpoints for $TARGET"

    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/file_upload.json"

    result=$(check_file_upload "$TARGET")
    IFS='|' read -r status found expected severity remediation_id <<< "$result"

    status_esc=$(json_escape "$status")
    found_esc=$(json_escape "$found")
    expected_esc=$(json_escape "$expected")
    severity_esc=$(json_escape "$severity")
    remediation_id_esc=$(json_escape "$remediation_id")

    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$TARGET\","
        echo "  \"checks\": ["
        echo "    {\"name\":\"File Upload Security\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "File upload check complete"
done
