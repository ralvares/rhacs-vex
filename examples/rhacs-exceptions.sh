#!/usr/bin/env bash
#
# rhacs-exceptions.sh - shell helpers for the RHACS vulnerability exception workflow
#
# Source this file from your shell (or from ~/.bashrc / ~/.zshrc):
#
#   source examples/rhacs-exceptions.sh
#
# Required environment:
#
#   export ROX_ENDPOINT=central.example.com:443     # RHACS Central, host:port
#   export ROX_API_TOKEN=<token>                    # needs VulnerabilityManagementRequests (write)
#
# Optional:
#
#   export ROX_APPROVER_TOKEN=<token>               # needs VulnerabilityManagementApprovals (write);
#                                                   # falls back to ROX_API_TOKEN if unset
#   export ROX_CA_FILE=/path/to/central-ca.pem      # verify TLS against Central's CA
#                                                   # (default: -k, TLS verification skipped)
#
# Requester commands:
#
#   rhacs-fp IMAGE CVE [CVE...] -m "comment" [--auto-approve]
#       Request a false positive exception, always scoped to the image.
#       IMAGE may be registry/repo:tag or registry/repo@sha256:...
#       Tagged image  -> scope registry/repo:tag
#       Digest image  -> scope registry/repo:.* (all tags of the repository)
#       --auto-approve approves immediately using ROX_APPROVER_TOKEN.
#
# Approver commands:
#
#   rhacs-exceptions [pending|approved|denied]   list requests (default: pending)
#   rhacs-exceptions-overview                    counts per status + pending detail
#   rhacs-approve ID [-m "comment"]              approve one request
#   rhacs-approve-all [-m "comment"] [-y]        approve every pending request
#   rhacs-cancel ID                              revert an approved exception (CVEs re-observed)
#   rhacs-cancel-all [-y]                        revert every approved exception (test cleanup)
#
# Examples:
#
#   Test 1 - single CVE. Scanner flags httpd 2.4.50-1.el9 for CVE-2023-25690,
#   but Red Hat fixed it in the 2.4.53-7.el9_1.5 backport: the version number
#   looks vulnerable, the patch is already in. Classic false positive.
#
#     rhacs-fp quay.io/vuln/asset-cache:v1 CVE-2023-25690 \
#         -m "False positive: fixed by RHEL9 backport httpd-2.4.53-7.el9_1.5, version match only"
#
#   Test 2 - multiple CVEs in one request, same image. All flagged against
#   httpd 2.4.50-1.el9 on version match; each is addressed by a RHEL9 backport.
#
#     rhacs-fp quay.io/vuln/asset-cache:v1 \
#         CVE-2023-25690 CVE-2024-38474 CVE-2024-38475 CVE-2024-38476 \
#         CVE-2024-38477 CVE-2025-58098 CVE-2026-28780 \
#         -m "False positives: httpd CVEs fixed by RHEL9 backports, scanner matched on version only"
#
#   Test 3 - auto-approve (token needs both request and approval permissions):
#
#     rhacs-fp quay.io/vuln/asset-cache:v1 CVE-2023-25690 \
#         -m "False positive: RHEL9 backport" --auto-approve
#
#   Approver flow:
#
#     rhacs-exceptions                 # see what is pending
#     rhacs-approve <id> -m "verified against Red Hat VEX"
#     rhacs-approve-all -m "verified batch against Red Hat VEX"
#
# Dependencies: curl, jq

# ---------------------------------------------------------------- internals

_rox_curl() {
    local method="$1" path="$2" body="${3:-}" token="${4:-$ROX_API_TOKEN}"
    local curl_bin insecure=(-k)
    [ -n "${ROX_CA_FILE:-}" ] && insecure=(--cacert "$ROX_CA_FILE")

    curl_bin=$(command -v curl) || curl_bin=/usr/bin/curl
    if [ ! -x "$curl_bin" ]; then
        echo "error: curl not found in PATH" >&2
        return 1
    fi

    if [ -z "${ROX_ENDPOINT:-}" ] || [ -z "${token:-}" ]; then
        echo "error: ROX_ENDPOINT and ROX_API_TOKEN must be set" >&2
        return 1
    fi

    if [ -n "$body" ]; then
        "$curl_bin" -sS "${insecure[@]}" -X "$method" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "$body" \
            "https://${ROX_ENDPOINT}${path}"
    else
        "$curl_bin" -sS "${insecure[@]}" -X "$method" \
            -H "Authorization: Bearer $token" \
            "https://${ROX_ENDPOINT}${path}"
    fi
}

# Split registry/repo[:tag][@sha256:...] into REGISTRY, REMOTE, TAG.
# Digest (or missing tag) -> TAG=".*"
_rox_parse_image() {
    local ref="$1" base tag="" last
    ref="${ref%%@*}"                      # drop @sha256:... if present
    last="${ref##*/}"
    if [ "${last#*:}" != "$last" ]; then  # tag present after last slash
        tag="${last#*:}"
        base="${ref%:*}"
    else
        base="$ref"
    fi
    [ -z "$tag" ] && tag=".*"

    REGISTRY="${base%%/*}"
    REMOTE="${base#*/}"
    TAG="$tag"

    if [ "$REGISTRY" = "$base" ] || [ -z "$REMOTE" ]; then
        echo "error: IMAGE must be a full reference like quay.io/org/app:tag or quay.io/org/app@sha256:..." >&2
        return 1
    fi
}

# ---------------------------------------------------------------- requester

rhacs-fp() {
    local cves=() comment="" auto_approve="" image=""

    while [ $# -gt 0 ]; do
        case "$1" in
            -m|--comment)   comment="$2"; shift 2 ;;
            --auto-approve) auto_approve=1; shift ;;
            -h|--help)
                echo 'usage: rhacs-fp IMAGE CVE [CVE...] -m "comment" [--auto-approve]'
                return 0 ;;
            *)
                if [ -z "$image" ]; then image="$1"; else cves+=("$1"); fi
                shift ;;
        esac
    done

    if [ -z "$image" ] || [ ${#cves[@]} -eq 0 ] || [ -z "$comment" ]; then
        echo 'usage: rhacs-fp IMAGE CVE [CVE...] -m "comment" [--auto-approve]' >&2
        return 1
    fi

    _rox_parse_image "$image" || return 1

    # Drop CVEs already covered by an active request for this exact scope,
    # so an existing (possibly approved) exception is never touched.
    local covered cve remaining=() skipped=()
    covered=$(_rox_curl GET "/v2/vulnerability-exceptions?query=$(jq -rn '"Request Status:PENDING,APPROVED,APPROVED_PENDING_UPDATE"|@uri')&pagination.limit=1000" |
        jq -r --arg registry "$REGISTRY" --arg remote "$REMOTE" --arg tag "$TAG" '
            .exceptions // [] | .[] |
            select(.expired != true) |
            select(.scope.imageScope.registry == $registry
               and .scope.imageScope.remote == $remote
               and .scope.imageScope.tag == $tag) |
            .cves[]' | sort -u)

    for cve in "${cves[@]}"; do
        if [ -n "$covered" ] && grep -qx "$cve" <<<"$covered"; then
            skipped+=("$cve")
        else
            remaining+=("$cve")
        fi
    done

    if [ ${#skipped[@]} -gt 0 ]; then
        echo "skipping (already covered by an active request for this scope): ${skipped[*]}"
    fi
    if [ ${#remaining[@]} -eq 0 ]; then
        echo "nothing to request: all CVEs already covered for this scope"
        return 0
    fi
    cves=("${remaining[@]}")

    local body response id name
    body=$(jq -n \
        --arg comment "$comment" \
        --arg registry "$REGISTRY" \
        --arg remote "$REMOTE" \
        --arg tag "$TAG" \
        --args '{
            cves: $ARGS.positional,
            comment: $comment,
            scope: { imageScope: { registry: $registry, remote: $remote, tag: $tag } }
        }' "${cves[@]}")

    response=$(_rox_curl POST /v2/vulnerability-exceptions/false-positive "$body") || return 1

    id=$(jq -r '.exception.id // empty' <<<"$response")
    if [ -z "$id" ]; then
        echo "request failed:" >&2
        jq -r '.message // .' <<<"$response" >&2
        return 1
    fi

    name=$(jq -r '.exception.name' <<<"$response")
    echo "created false positive request: $name ($id)"
    echo "  scope: $REGISTRY/$REMOTE:$TAG"
    echo "  cves:  ${cves[*]}"

    if [ -n "$auto_approve" ]; then
        rhacs-approve "$id" -m "Auto-approved: $comment"
    fi
}

# ---------------------------------------------------------------- approver

rhacs-exceptions() {
    local state="${1:-pending}" query
    case "$state" in
        pending)  query='Request Status:PENDING,APPROVED_PENDING_UPDATE' ;;
        approved) query='Request Status:APPROVED' ;;
        denied)   query='Request Status:DENIED' ;;
        *) echo "usage: rhacs-exceptions [pending|approved|denied]" >&2; return 1 ;;
    esac

    _rox_curl GET "/v2/vulnerability-exceptions?query=$(jq -rn --arg q "$query" '$q|@uri')&pagination.limit=100" \
        "" "${ROX_APPROVER_TOKEN:-$ROX_API_TOKEN}" |
    jq -r '
        .exceptions // [] |
        if length == 0 then "no requests" else
        (["ID","NAME","TYPE","STATUS","REQUESTER","SCOPE","CVES"] | @tsv),
        (.[] | [
            .id,
            .name,
            (if .deferralRequest then "DEFERRAL" else "FALSE_POSITIVE" end),
            .status,
            (.requester.name // "-"),
            "\(.scope.imageScope.registry)/\(.scope.imageScope.remote):\(.scope.imageScope.tag)",
            (.cves | join(","))
        ] | @tsv)
        end' | column -t -s $'\t'
}

rhacs-exceptions-overview() {
    local token="${ROX_APPROVER_TOKEN:-$ROX_API_TOKEN}"
    echo "== exception requests by status"
    _rox_curl GET "/v2/vulnerability-exceptions?pagination.limit=1000" "" "$token" |
        jq -r '.exceptions // [] | group_by(.status) | map("\(.[0].status): \(length)") | .[]'
    echo
    echo "== pending detail"
    rhacs-exceptions pending
}

rhacs-approve() {
    local id="" comment="Approved via CLI"
    while [ $# -gt 0 ]; do
        case "$1" in
            -m|--comment) comment="$2"; shift 2 ;;
            *) id="$1"; shift ;;
        esac
    done
    if [ -z "$id" ]; then
        echo 'usage: rhacs-approve ID [-m "comment"]' >&2
        return 1
    fi

    local body response result
    body=$(jq -n --arg id "$id" --arg comment "$comment" '{id: $id, comment: $comment}')
    response=$(_rox_curl POST "/v2/vulnerability-exceptions/$id/approve" "$body" \
        "${ROX_APPROVER_TOKEN:-$ROX_API_TOKEN}") || return 1

    result=$(jq -r '.exception.status // empty' <<<"$response")
    if [ "$result" = "APPROVED" ]; then
        echo "approved: $(jq -r '.exception.name' <<<"$response") ($id)"
    else
        echo "approve failed for $id:" >&2
        jq -r '.message // .' <<<"$response" >&2
        return 1
    fi
}

rhacs-cancel() {
    local id="${1:-}"
    if [ -z "$id" ]; then
        echo "usage: rhacs-cancel ID    (find IDs with: rhacs-exceptions approved)" >&2
        return 1
    fi

    local response result
    response=$(_rox_curl POST "/v2/vulnerability-exceptions/$id/cancel" '{}' \
        "${ROX_APPROVER_TOKEN:-$ROX_API_TOKEN}") || return 1

    result=$(jq -r '.exception.id // empty' <<<"$response")
    if [ -n "$result" ]; then
        echo "canceled: $(jq -r '.exception.name' <<<"$response") ($id)"
        echo "  its CVEs return to Observed"
    else
        echo "cancel failed for $id:" >&2
        jq -r '.message // .' <<<"$response" >&2
        return 1
    fi
}

rhacs-cancel-all() {
    local yes=""
    case "${1:-}" in -y|--yes) yes=1 ;; esac

    local ids
    ids=$(_rox_curl GET "/v2/vulnerability-exceptions?query=$(jq -rn '"Request Status:APPROVED"|@uri')&pagination.limit=1000" \
        "" "${ROX_APPROVER_TOKEN:-$ROX_API_TOKEN}" | jq -r '.exceptions // [] | .[] | select(.expired != true) | .id')

    if [ -z "$ids" ]; then
        echo "nothing approved to cancel"
        return 0
    fi

    echo "approved exceptions:"
    rhacs-exceptions approved
    echo

    if [ -z "$yes" ]; then
        printf 'cancel ALL of the above? CVEs will return to Observed. [y/N] '
        read -r answer
        case "$answer" in y|Y|yes) ;; *) echo "aborted"; return 1 ;; esac
    fi

    local id ok=0 fail=0
    while IFS= read -r id; do
        [ -z "$id" ] && continue
        if rhacs-cancel "$id" >/dev/null; then
            echo "canceled: $id"; ok=$((ok+1))
        else
            fail=$((fail+1))
        fi
    done <<<"$ids"
    echo "done: $ok canceled, $fail failed"
}

rhacs-approve-all() {
    local comment="Bulk-approved via CLI" yes=""
    while [ $# -gt 0 ]; do
        case "$1" in
            -m|--comment) comment="$2"; shift 2 ;;
            -y|--yes)     yes=1; shift ;;
            *) echo 'usage: rhacs-approve-all [-m "comment"] [-y]' >&2; return 1 ;;
        esac
    done

    local ids
    ids=$(_rox_curl GET "/v2/vulnerability-exceptions?query=$(jq -rn '"Request Status:PENDING"|@uri')&pagination.limit=1000" \
        "" "${ROX_APPROVER_TOKEN:-$ROX_API_TOKEN}" | jq -r '.exceptions // [] | .[].id')

    if [ -z "$ids" ]; then
        echo "nothing pending"
        return 0
    fi

    echo "pending requests:"
    rhacs-exceptions pending
    echo

    if [ -z "$yes" ]; then
        printf 'approve ALL of the above? [y/N] '
        read -r answer
        case "$answer" in y|Y|yes) ;; *) echo "aborted"; return 1 ;; esac
    fi

    local id ok=0 fail=0
    while IFS= read -r id; do
        [ -z "$id" ] && continue
        if rhacs-approve "$id" -m "$comment"; then ok=$((ok+1)); else fail=$((fail+1)); fi
    done <<<"$ids"
    echo "done: $ok approved, $fail failed"
}
