#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step4_cloud_storage"

# Check for exposed public cloud storage buckets (AWS S3, GCS, Azure Blob)
check_cloud_storage() {
    local target="$1"
    local hostname
    hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's/:.*$//')

    # Derive basename for bucket guessing (strip www., strip TLD)
    local base_name
    base_name=$(echo "$hostname" | sed 's/^www\.//' | cut -d'.' -f1)

    local issues=()
    local severity="INFO"

    # Common bucket name patterns to test
    local bucket_names=("$base_name" "${base_name}-assets" "${base_name}-static" "${base_name}-media" "${base_name}-backup" "${base_name}-uploads" "${base_name}-data" "${base_name}-public" "${base_name}-files" "${base_name}-dev")

    for bucket in "${bucket_names[@]}"; do
        # --- AWS S3 ---
        local s3_url="https://${bucket}.s3.amazonaws.com/"
        local s3_response
        s3_response=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$s3_url" 2>/dev/null || echo "")

        local s3_status
        s3_status=$(echo "$s3_response" | grep -E "^HTTP/" | tail -1 | awk '{print $2}')

        if [[ "$s3_status" == "200" ]]; then
            issues+=("Public S3 bucket accessible: $s3_url (HTTP 200)")
            severity="CRITICAL"
        elif [[ "$s3_status" == "403" ]]; then
            issues+=("S3 bucket exists but access denied: $bucket (may be misconfigured)")
            [[ "$severity" == "INFO" ]] && severity="MEDIUM"
        fi

        # --- GCS (Google Cloud Storage) ---
        local gcs_url="https://storage.googleapis.com/${bucket}/"
        local gcs_response
        gcs_response=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$gcs_url" 2>/dev/null || echo "")

        local gcs_status
        gcs_status=$(echo "$gcs_response" | grep -E "^HTTP/" | tail -1 | awk '{print $2}')

        if [[ "$gcs_status" == "200" ]]; then
            issues+=("Public GCS bucket accessible: $gcs_url (HTTP 200)")
            severity="CRITICAL"
        elif [[ "$gcs_status" == "403" ]]; then
            issues+=("GCS bucket exists but access denied: $bucket")
            [[ "$severity" == "INFO" ]] && severity="MEDIUM"
        fi

        # --- Azure Blob Storage ---
        local az_url="https://${base_name}.blob.core.windows.net/${bucket}/"
        local az_response
        az_response=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$az_url" 2>/dev/null || echo "")

        local az_status
        az_status=$(echo "$az_response" | grep -E "^HTTP/" | tail -1 | awk '{print $2}')

        if [[ "$az_status" == "200" ]]; then
            issues+=("Public Azure Blob container accessible: $az_url (HTTP 200)")
            severity="CRITICAL"
        fi
    done

    if [[ ${#issues[@]} -eq 0 ]]; then
        echo "PASS|No exposed public cloud storage buckets detected|Cloud storage buckets private and secured|INFO|"
        return
    fi

    local issues_str
    issues_str=$(IFS="; "; printf '%s' "${issues[*]}")

    if [[ "$severity" == "CRITICAL" ]]; then
        echo "FAIL|$issues_str|Immediately restrict bucket ACLs to private; enable access logging|CRITICAL|SEC-CLOUD-002"
    else
        echo "WARN|$issues_str|Verify bucket ACLs; ensure no sensitive data exposed|$severity|SEC-CLOUD-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking cloud storage exposure for $TARGET"

    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/cloud_storage.json"

    result=$(check_cloud_storage "$TARGET")

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
        echo "    {\"name\":\"Cloud Storage Exposure\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "Cloud storage exposure check complete"
done
