#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step4_backup_files"

check_backup_files() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    local hostname
    hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's/:.*$//')
    local basename
    basename=$(echo "$hostname" | sed 's/^www\.//' | cut -d'.' -f1)

    local backup_paths=(
        "/backup.sql" "/backup.zip" "/backup.tar.gz" "/${basename}.sql"
        "/${basename}.zip" "/database.sql" "/db.sql" "/dump.sql"
        "/wp-config.php.bak" "/wp-config.bak" "/wp-config.php~" "/wp-config.old"
        "/.git/config" "/.env.bak" "/.env.old" "/.env.backup"
        "/site.tar.gz" "/site.zip" "/website.zip" "/files.zip"
        "/backup/" "/backups/" "/old/" "/archive/"
        "/${basename}_backup.zip" "/${basename}-backup.sql"
        "/error_log" "/error.log" "/access.log" "/debug.log"
        "/wp-content/debug.log" "/php_errorlog"
    )

    local found_files=()
    local severity="INFO"

    for path in "${backup_paths[@]}"; do
        local url="${base_url}${path}"
        local http_code
        http_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null || echo "000")

        if [[ "$http_code" == "200" ]]; then
            # Verify it's not a soft-404 by checking content type and size
            local content_type size
            headers=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null || echo "")
            content_type=$(echo "$headers" | grep -i "^Content-Type:" | head -1 | sed 's/^[Cc]ontent-[Tt]ype: //;s/\r//')
            size=$(echo "$headers" | grep -i "^Content-Length:" | head -1 | sed 's/^[Cc]ontent-[Ll]ength: //;s/\r//' || echo "0")

            # Skip HTML responses (likely soft-404s) unless it's a log
            if echo "$content_type" | grep -qi "text/html" && ! echo "$path" | grep -qiE "\.log|error_log"; then
                continue
            fi

            # Check content preview for sensitive data signals
            local preview
            preview=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null | head -c 512 || echo "")

            if echo "$preview" | grep -qiE "CREATE TABLE|INSERT INTO|DB_PASSWORD|DB_HOST|define\(|<?php|BEGIN PGP|PRIVATE KEY|-{5}BEGIN" 2>/dev/null; then
                found_files+=("$path (CRITICAL: contains sensitive data)")
                severity="CRITICAL"
            else
                found_files+=("$path (HTTP 200, size: ${size:-unknown})")
                [[ "$severity" == "INFO" ]] && severity="HIGH"
            fi
        fi
    done

    if [[ ${#found_files[@]} -eq 0 ]]; then
        echo "PASS|No backup or sensitive archive files found at common paths|Backups stored outside web root|INFO|"
        return
    fi

    local files_str
    files_str=$(IFS="; "; printf '%s' "${found_files[*]}")

    if [[ "$severity" == "CRITICAL" ]]; then
        echo "FAIL|$files_str|Immediately remove files; move backups outside web root; rotate credentials|CRITICAL|SEC-BACKUP-002"
    else
        echo "FAIL|$files_str|Remove backup/archive files from web root; restrict access to backups directory|HIGH|SEC-BACKUP-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking for exposed backup files for $TARGET"

    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/backup_files.json"

    result=$(check_backup_files "$TARGET")
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
        echo "    {\"name\":\"Backup File Exposure\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "Backup file check complete"
done
