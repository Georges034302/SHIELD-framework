#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step4_graphql"

# Check for GraphQL introspection enabled (information disclosure risk)
check_graphql() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    local graphql_endpoints=("/graphql" "/api/graphql" "/graphql/console" "/v1/graphql" "/api/v1/graphql")

    local introspection_payload='{"query":"{ __schema { queryType { name } } }"}'
    local issues=()
    local severity="INFO"

    for ep in "${graphql_endpoints[@]}"; do
        local url="${base_url}${ep}"

        local response
        response=$(curl -sS -X POST \
            -H "Content-Type: application/json" \
            -d "$introspection_payload" \
            --max-time "${TIMEOUT:-10}" \
            "$url" 2>/dev/null || echo "")

        # Check for a successful introspection response
        if echo "$response" | grep -q "__schema"; then
            issues+=("GraphQL introspection enabled at $ep")
            severity="HIGH"
        fi

        # Check for GraphQL playground / console exposed
        local get_response
        get_response=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null || echo "")
        if echo "$get_response" | grep -qi "graphql\|playground\|graphiql"; then
            issues+=("GraphQL playground/IDE exposed at $ep")
            [[ "$severity" == "INFO" ]] && severity="MEDIUM"
        fi
    done

    if [[ ${#issues[@]} -eq 0 ]]; then
        echo "PASS|No GraphQL introspection or exposed endpoints found|GraphQL introspection disabled in production|INFO|"
        return
    fi

    local issues_str
    issues_str=$(IFS=", "; printf '%s' "${issues[*]}")

    if [[ ${#issues[@]} -ge 2 ]]; then
        echo "FAIL|$issues_str|Disable introspection in production; restrict playground access|$severity|SEC-GRAPHQL-002"
    else
        echo "FAIL|$issues_str|Disable GraphQL introspection in production environments|$severity|SEC-GRAPHQL-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking GraphQL introspection for $TARGET"

    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/graphql.json"

    result=$(check_graphql "$TARGET")

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
        echo "    {\"name\":\"GraphQL Introspection\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "GraphQL introspection check complete"
done
