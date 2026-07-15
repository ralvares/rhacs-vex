#!/usr/bin/env bash
#
# rhacs-report-migrate.sh - migrate RHACS vulnerability report configurations
# from the deprecated "Collection scope" to the new "Custom scope".
#
# Source this file from your shell (or from ~/.bashrc / ~/.zshrc):
#
#   source examples/rhacs-report-migrate.sh
#
# Required environment (same as rhacs-exceptions.sh):
#
#   export ROX_ENDPOINT=central.example.com:443
#   export ROX_API_TOKEN=<token>       # needs WorkflowAdministration (write) + read on Config/Collections
#
# Optional:
#
#   export ROX_CA_FILE=/path/ca.pem    # verify TLS (default: -k, verification skipped)
#
# Commands:
#
#   rhacs-report-migrate               list report configs still using a collection scope
#   rhacs-report-migrate ID [-y]       migrate one config, updating it IN PLACE (same name/ID)
#   rhacs-report-migrate-all [-y]      migrate every collection-scoped config in place
#
# What the migration does:
#
#   - Translates the collection's rules (cluster / namespace / deployment,
#     name / label / annotation, exact / regex) into custom scope rules.
#   - Detects platform reports: if every namespace in the collection matches
#     the platform definition (built-in + custom platform components), the new
#     report filters on Area of concern = Platform. If none do, it filters on
#     Area of concern = User workload. Mixed collections get no area filter.
#   - Always adds "Vulnerability State: OBSERVED": reports contain only active
#     findings, never deferred or false-positive CVEs.
#   - Carries severity and fixability filters into the new query, and keeps
#     schedule, notifiers, image types and the CVEs-discovered-since setting.
#   - The configuration is UPDATED IN PLACE: same name, same ID, no duplicate.
#
# Limitations (the script warns and refuses when it cannot map faithfully):
#
#   - Collections with embedded collections are not supported.
#   - Collections with more than one resource selector group are not supported
#     (custom scope has a single rule set).
#
# Dependencies: curl, jq

_roxr_curl() {
    local method="$1" path="$2" body="${3:-}"
    local curl_bin tls=(-k)
    [ -n "${ROX_CA_FILE:-}" ] && tls=(--cacert "$ROX_CA_FILE")

    curl_bin=$(command -v curl) || curl_bin=/usr/bin/curl
    if [ -z "${ROX_ENDPOINT:-}" ] || [ -z "${ROX_API_TOKEN:-}" ]; then
        echo "error: ROX_ENDPOINT and ROX_API_TOKEN must be set" >&2
        return 1
    fi

    if [ -n "$body" ]; then
        "$curl_bin" -sS "${tls[@]}" -X "$method" \
            -H "Authorization: Bearer $ROX_API_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$body" \
            "https://${ROX_ENDPOINT}${path}"
    else
        "$curl_bin" -sS "${tls[@]}" -X "$method" \
            -H "Authorization: Bearer $ROX_API_TOKEN" \
            "https://${ROX_ENDPOINT}${path}"
    fi
}

# jq program: collection rules -> entity scope rules
_ROXR_JQ_COLRULES='
def fieldmap: {
    "Cluster":               {entity: "SCOPE_ENTITY_CLUSTER",    field: "FIELD_NAME"},
    "Cluster Label":         {entity: "SCOPE_ENTITY_CLUSTER",    field: "FIELD_LABEL"},
    "Namespace":             {entity: "SCOPE_ENTITY_NAMESPACE",  field: "FIELD_NAME"},
    "Namespace Label":       {entity: "SCOPE_ENTITY_NAMESPACE",  field: "FIELD_LABEL"},
    "Namespace Annotation":  {entity: "SCOPE_ENTITY_NAMESPACE",  field: "FIELD_ANNOTATION"},
    "Deployment":            {entity: "SCOPE_ENTITY_DEPLOYMENT", field: "FIELD_NAME"},
    "Deployment Label":      {entity: "SCOPE_ENTITY_DEPLOYMENT", field: "FIELD_LABEL"},
    "Deployment Annotation": {entity: "SCOPE_ENTITY_DEPLOYMENT", field: "FIELD_ANNOTATION"}
};
(.resourceSelectors[0].rules // []) as $crules
| ($crules | map(.fieldName) | map(select(fieldmap[.] == null))) as $unknown
| if ($unknown | length) > 0 then error("unmappable collection field(s): \($unknown | join(", "))") else . end
| $crules | map({
      entity: fieldmap[.fieldName].entity,
      field:  fieldmap[.fieldName].field,
      values: [.values[] | {value, matchType: (.matchType // "EXACT")}]
  })
'

# jq program that builds the new configuration.
# Inputs: $cfg (report config), $rules (entity scope rules),
#         $platform (platform component regexes), $allns (live namespace names)
_ROXR_JQ_TRANSFORM='
# platform detection: resolve namespace-name values to concrete namespaces
# (EXACT values stand alone; REGEX values are matched against the live
# namespace list), then classify each against the platform component regexes
([$rules[] | select(.entity == "SCOPE_ENTITY_NAMESPACE" and .field == "FIELD_NAME") | .values[]]) as $nsvals
| ($nsvals | map(
      . as $v |
      if $v.matchType == "EXACT"
      then [$v.value]
      else [$allns[] | select(. as $ns | $v.value as $re | $ns | test($re))]
      end
  ) | flatten | unique) as $concrete
| ($concrete | map(. as $ns | any($platform[]; . as $re | $ns | test($re)))) as $flags
| (if ($flags | length) == 0 then "none"
   elif all($flags[]; .)     then "platform"
   elif any($flags[]; .)     then "mixed"
   else "workload" end) as $area

# query: keep existing filters, carry legacy severity/fixability over,
# state always OBSERVED, area of concern always set
| (($cfg.vulnReportFilters.query // "") | split("+")
   | map(select(length > 0
       and (startswith("Vulnerability State:") | not)
       and (startswith("Platform Component:") | not)))) as $existing
| (($existing
   + (if ($cfg.vulnReportFilters.severities // []) | length > 0
      then ["Severity:" + ($cfg.vulnReportFilters.severities | join(","))]
      else [] end)
   + (if   $cfg.vulnReportFilters.fixability == "FIXABLE"     then ["Fixable:true"]
      elif $cfg.vulnReportFilters.fixability == "NOT_FIXABLE" then ["Fixable:false"]
      else [] end)
   + ["Vulnerability State:OBSERVED"]
   + [if   $area == "platform" then "Platform Component:true"
      elif $area == "workload" then "Platform Component:false"
      else "Platform Component:true,false" end]
  ) | join("+")) as $query

| {
    namespaces: $concrete,
    nonplatform: [$concrete[] | select(. as $ns | any($platform[]; . as $re | $ns | test($re)) | not)],
    config: ($cfg
        | .resourceScope = {entityScope: {rules: $rules}}
        | .vulnReportFilters.query = $query
        | .vulnReportFilters.fixability = "BOTH"
        | .vulnReportFilters.severities = []
    ),
    area: $area,
    query: $query,
    rules: $rules
  }
'

rhacs-report-migrate() {
    local id="${1:-}" yes=""
    case "${2:-}" in -y|--yes) yes=1 ;; esac

    # No argument: list configs that still use a collection scope.
    if [ -z "$id" ]; then
        echo "report configurations still using Collection scope:"
        _roxr_curl GET "/v2/reports/configurations?pagination.limit=1000" |
        jq -r '
            [.reportConfigs // [] | .[] | select(.resourceScope.collectionScope != null)] |
            if length == 0 then "  none - nothing to migrate" else
            (["ID","NAME","COLLECTION"] | @tsv),
            (.[] | [.id, .name, .resourceScope.collectionScope.collectionName] | @tsv)
            end' | column -t -s $'\t'
        echo
        echo 'migrate one with: rhacs-report-migrate <ID>'
        return 0
    fi

    local cfg colid col rules platform plan
    cfg=$(_roxr_curl GET "/v2/reports/configurations/$id") || return 1
    if [ -n "$(jq -r '.message // empty' <<<"$cfg")" ]; then
        echo "error: config not found:" >&2
        jq -r '.message' <<<"$cfg" >&2
        return 1
    fi

    if [ "$(jq -r '.resourceScope.collectionScope // empty' <<<"$cfg")" != "" ]; then
        # Collection-scoped: translate the collection into custom scope rules.
        colid=$(jq -r '.resourceScope.collectionScope.collectionId' <<<"$cfg")
        col=$(_roxr_curl GET "/v1/collections/$colid" | jq '.collection') || return 1

        if [ "$(jq -r '.embeddedCollections | length' <<<"$col")" != "0" ]; then
            echo "error: collection has embedded collections; migrate it manually" >&2
            return 1
        fi
        if [ "$(jq -r '.resourceSelectors | length' <<<"$col")" -gt 1 ]; then
            echo "error: collection has multiple resource selector groups; migrate it manually" >&2
            return 1
        fi
        rules=$(jq "$_ROXR_JQ_COLRULES" <<<"$col" 2>&1) || { echo "error: $rules" >&2; return 1; }
    elif [ "$(jq -r '.resourceScope.entityScope // empty' <<<"$cfg")" != "" ]; then
        # Already custom scope: re-evaluate the filters against the current
        # platform definition (keeps the scope rules as they are).
        rules=$(jq '.resourceScope.entityScope.rules' <<<"$cfg")
    else
        echo "error: config has no collection or custom scope" >&2
        return 1
    fi

    # Platform definition: built-in + custom platform component regexes.
    platform=$(_roxr_curl GET "/v1/config" |
        jq '[.platformComponentConfig.rules // [] | .[] | .namespaceRule.regex] | map(select(. != null and . != ""))')

    # Live namespaces, to resolve regex-valued namespace rules.
    local allns
    allns=$(_roxr_curl GET "/v1/namespaces" | jq '[.namespaces[].metadata.name] | unique')

    plan=$(jq -n --argjson cfg "$cfg" --argjson rules "$rules" --argjson platform "$platform" \
        --argjson allns "$allns" "$_ROXR_JQ_TRANSFORM" 2>&1) || { echo "error: $plan" >&2; return 1; }

    echo "migration plan for: $(jq -r '.name' <<<"$cfg") (updated in place, same name and ID)"
    echo
    echo "  new scope:"
    jq -r '.rules[] | "    \(.entity | sub("SCOPE_ENTITY_";"")) \(.field | sub("FIELD_";"") | ascii_downcase): \([.values[] | "\(.value) (\(.matchType))"] | join(", "))"' <<<"$plan"
    echo "  filters:   $(jq -r '.query' <<<"$plan")"
    echo "  resolves to namespaces: $(jq -r '.namespaces | if length == 0 then "(none/unknown)" else join(", ") end' <<<"$plan")" | fold -s -w 100
    case "$(jq -r '.area' <<<"$plan")" in
        platform) echo "  detected:  all namespaces are platform -> Area of concern = Platform" ;;
        workload) echo "  detected:  no platform namespaces -> Area of concern = User workload" ;;
        none)     echo "  detected:  no namespace rules -> Area of concern = Platform + User workload" ;;
        mixed)
            echo "  detected:  mixed namespaces -> Area of concern = Platform + User workload"
            echo "  not covered by the platform definition:"
            jq -r '.nonplatform[] | "    " + .' <<<"$plan"
            echo "  hint: if these belong to the platform, add them under Platform Configuration ->"
            echo "        System Configuration -> Platform components configuration -> Custom components,"
            echo "        then re-run this migration to get Area of concern = Platform."
            ;;
    esac
    echo

    if [ -z "$yes" ]; then
        printf 'update this report configuration in place? [y/N] '
        read -r answer
        case "$answer" in y|Y|yes) ;; *) echo "aborted"; return 1 ;; esac
    fi

    local response
    response=$(_roxr_curl PUT "/v2/reports/configurations/$id" "$(jq -c '.config' <<<"$plan")") || return 1
    if [ -n "$(jq -r '.message // empty' <<<"$response")" ]; then
        echo "update failed:" >&2
        jq -r '.message' <<<"$response" >&2
        return 1
    fi

    echo "updated in place: $(jq -r '.name' <<<"$cfg") ($id) now uses Custom scope"
}

rhacs-report-migrate-all() {
    local yes=""
    case "${1:-}" in -y|--yes) yes=1 ;; esac

    local configs candidates
    configs=$(_roxr_curl GET "/v2/reports/configurations?pagination.limit=1000") || return 1

    candidates=$(jq -r '
        .reportConfigs // [] | .[] |
        select(.resourceScope.collectionScope != null) |
        .id + "\t" + .name' <<<"$configs")

    if [ -z "$candidates" ]; then
        echo "nothing to migrate: no report configurations use a collection scope"
        return 0
    fi

    echo "will migrate:"
    printf '%s\n' "$candidates" | column -t -s $'\t'
    echo

    if [ -z "$yes" ]; then
        printf 'migrate ALL of the above? [y/N] '
        read -r answer
        case "$answer" in y|Y|yes) ;; *) echo "aborted"; return 1 ;; esac
    fi

    local id name ok=0 fail=0
    while IFS=$'\t' read -r id name; do
        [ -z "$id" ] && continue
        echo "--- migrating: $name"
        if rhacs-report-migrate "$id" -y; then ok=$((ok+1)); else fail=$((fail+1)); fi
        echo
    done <<<"$candidates"
    echo "done: $ok migrated, $fail failed/skipped"
}
