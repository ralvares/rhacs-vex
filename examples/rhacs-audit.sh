#!/usr/bin/env bash
#
# rhacs-audit.sh - read-only security audits pulled from the RHACS API.
#
# Source this file from your shell (or from ~/.bashrc / ~/.zshrc):
#
#   source examples/rhacs-audit.sh
#
# Required environment (same as the other helpers):
#
#   export ROX_ENDPOINT=central.example.com:443
#   export ROX_API_TOKEN=<token>       # read access: K8sRole, K8sRoleBinding, K8sSubject,
#                                      # Secret, Deployment, Image, Administration
#
# Optional:
#
#   export ROX_CA_FILE=/path/ca.pem    # verify TLS (default: -k, verification skipped)
#
# Commands (all read-only):
#
#   rhacs-rbac-audit [--all]         RBAC blast radius: risky roles (wildcards,
#                                    escalate/impersonate/bind, secrets access) and
#                                    every subject bound to them. Platform noise
#                                    (system: roles, openshift-*/kube-* namespaces)
#                                    hidden unless --all
#   rhacs-cert-expiry [DAYS]         TLS certificates inside cluster secrets expiring
#                                    within DAYS (default 30), plus Central's own
#                                    service certificates
#   rhacs-patch-queue [N]            top N deployments by RHACS risk priority with
#                                    their fixable CVE counts: a patch plan ordered
#                                    by real exposure (default 15)
#
# Dependencies: curl, jq

_roxa_curl() {
    local method="$1" path="$2"
    local curl_bin tls=(-k)
    [ -n "${ROX_CA_FILE:-}" ] && tls=(--cacert "$ROX_CA_FILE")
    curl_bin=$(command -v curl) || curl_bin=/usr/bin/curl

    if [ -z "${ROX_ENDPOINT:-}" ] || [ -z "${ROX_API_TOKEN:-}" ]; then
        echo "error: ROX_ENDPOINT and ROX_API_TOKEN must be set" >&2
        return 1
    fi

    "$curl_bin" -sS --retry 2 --retry-all-errors "${tls[@]}" -X "$method" \
        -H "Authorization: Bearer $ROX_API_TOKEN" \
        "https://${ROX_ENDPOINT}${path}"
}

# ------------------------------------------------------------ RBAC blast radius

rhacs-rbac-audit() {
    local all=""
    case "${1:-}" in --all) all=1 ;; esac
    local roles bindings
    roles=$(_roxa_curl GET "/v1/rbac/roles") || return 1
    # Default: hide platform noise (system: roles, openshift-*/kube-* namespaces).
    if [ -z "$all" ]; then
        roles=$(jq '{roles: [.roles[]
            | select(.name | startswith("system:") | not)
            | select((.namespace // "") | test("^(openshift-|openshift$|kube-)") | not)]}' <<<"$roles")
    fi
    bindings=$(_roxa_curl GET "/v1/rbac/bindings") || return 1

    # Classify risky roles. A role can be risky for several reasons.
    local risky
    risky=$(jq '
        [ .roles[] | . as $r |
          ([ (if ([$r.rules[]? | select((.verbs | index("*")) and (.resources | index("*")) and (.apiGroups | index("*")))] | length) > 0
              then "full-admin (*/*/*)" else empty end),
             (if ([$r.rules[]? | .verbs[]? | select(. == "escalate" or . == "impersonate" or . == "bind")] | length) > 0
              then "escalate/impersonate/bind" else empty end),
             (if ([$r.rules[]? | select((.resources | index("secrets")) and ((.verbs | index("get")) or (.verbs | index("list")) or (.verbs | index("*"))))] | length) > 0
              then "reads secrets" else empty end),
             (if ([$r.rules[]? | select(((.resources | index("pods/exec")) or (.resources | index("pods/attach"))) )] | length) > 0
              then "pod exec/attach" else empty end)
           ]) as $reasons |
          select(($reasons | length) > 0) |
          {id: $r.id, name: $r.name, clusterName: $r.clusterName,
           scope: (if $r.clusterRole then "ClusterRole" else ("Role in " + $r.namespace) end),
           reasons: ($reasons | join(", "))}
        ]' <<<"$roles")

    echo "== risky roles"
    jq -r '
        if length == 0 then "none found" else
        (["ROLE","SCOPE","CLUSTER","WHY RISKY"] | @tsv),
        (.[] | [.name, .scope, .clusterName, .reasons] | @tsv)
        end' <<<"$risky" | column -t -s $'\t'

    echo
    echo "== subjects bound to risky roles"
    jq -r --argjson risky "$risky" '
        ($risky | map({(.id): .name}) | add // {}) as $riskymap |
        [ .bindings[] | select($riskymap[.roleId] != null) | . as $b |
          .subjects[]? |
          {kind, name,
           where: (if ($b.namespace // "") == "" then "cluster-wide" else $b.namespace end),
           cluster: $b.clusterName,
           role: $riskymap[$b.roleId]}
        ] |
        if length == 0 then "none found" else
        unique_by([.kind, .name, .where, .cluster, .role]) |
        (["KIND","SUBJECT","GRANTED IN","CLUSTER","RISKY ROLE"] | @tsv),
        (.[] | [.kind, .name, .where, .cluster, .role] | @tsv)
        end' <<<"$bindings" | column -t -s $'\t'
}

# ------------------------------------------------------------ certificate expiry

rhacs-cert-expiry() {
    local days="${1:-30}"

    echo "== Central service certificates"
    local comp
    for comp in CENTRAL CENTRAL_DB SCANNER SCANNER_V4; do
        _roxa_curl GET "/v1/credentialexpiry?component=$comp" |
            jq -r --arg c "$comp" '
                if .expiry then
                    ($c + "\t" + .expiry + "\t" +
                     (((.expiry | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) - now) / 86400 | floor | tostring) + " days")
                else ($c + "\tn/a\t-") end' 2>/dev/null || echo -e "$comp\tn/a\t-"
    done | column -t -s $'\t'

    echo
    echo "== TLS certificates in secrets expiring within $days days"

    # Only fetch secrets that actually contain certificates.
    local ids tmpdir
    ids=$(_roxa_curl GET "/v1/secrets?pagination.limit=1000" |
        jq -r '.secrets[] | select(.types | index("PUBLIC_CERTIFICATE") or index("CERT_PRIVATE_KEY")) | .id')
    if [ -z "$ids" ]; then
        echo "no certificate-bearing secrets found"
        return 0
    fi

    tmpdir=$(mktemp -d)
    # Subshell keeps background-job chatter out of interactive shells.
    (
        local id batch=0
        while IFS= read -r id; do
            [ -z "$id" ] && continue
            _roxa_curl GET "/v1/secrets/$id" > "$tmpdir/$id.json" &
            batch=$((batch+1))
            if [ "$batch" -ge 8 ]; then wait; batch=0; fi
        done <<<"$ids"
        wait
    )

    jq -rs --argjson days "$days" '
        [ .[] | .secret? // . |
          . as $s | .files[]? | select(.cert.endDate != null) |
          {ns: $s.namespace, secret: $s.name, cluster: $s.clusterName,
           file: .name, cn: (.cert.subject.commonName // "-"),
           end: .cert.endDate,
           left: (((.cert.endDate | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601) - now) / 86400 | floor)}
          | select(.left <= $days)
        ] | sort_by(.left) |
        if length == 0 then "none expiring within \($days) days" else
        (["DAYS LEFT","NAMESPACE","SECRET","FILE","CN","EXPIRES"] | @tsv),
        (.[] | [(.left | tostring), .ns, .secret, .file, .cn, .end] | @tsv)
        end' "$tmpdir"/*.json | column -t -s $'\t'
    rm -rf "$tmpdir"
}

# ------------------------------------------------------------ risk-ranked patch queue

rhacs-patch-queue() {
    local n="${1:-15}"

    # RHACS risk priority: 1 = riskiest deployment in the system.
    local deps
    deps=$(_roxa_curl GET "/v1/deployments?pagination.limit=1000" |
        jq --argjson n "$n" '[.deployments[]] | sort_by(.priority) | .[0:$n]')

    if [ "$(jq 'length' <<<"$deps")" = "0" ]; then
        echo "no deployments found"
        return 0
    fi

    local tmpdir i count
    tmpdir=$(mktemp -d)
    count=$(jq 'length' <<<"$deps")
    i=0
    ( # subshell: no background-job chatter in interactive shells
    while [ "$i" -lt "$count" ]; do
        (
            local d ns name q
            d=$(jq -c ".[$i]" <<<"$deps")
            ns=$(jq -r '.namespace' <<<"$d")
            name=$(jq -r '.name' <<<"$d")
            q=$(jq -rn --arg q "Namespace:$ns+Deployment:$name" '$q|@uri')
            _roxa_curl GET "/v1/images?query=$q" |
                jq --argjson d "$d" '{
                    priority: $d.priority, cluster: $d.cluster,
                    ns: $d.namespace, name: $d.name,
                    images: ([.images[]?] | length),
                    cves: ([.images[]?.cves] | add // 0),
                    fixable: ([.images[]?.fixableCves] | add // 0)
                }' > "$tmpdir/$(printf '%04d' "$i").json"
        ) &
        i=$((i+1))
        if [ $((i % 8)) -eq 0 ]; then wait; fi
    done
    wait
    )

    echo "top $n deployments by RHACS risk, with fixable CVEs (patch these first):"
    jq -rs '
        sort_by(.priority) |
        (["RANK","CLUSTER","NAMESPACE","DEPLOYMENT","IMAGES","CVES","FIXABLE"] | @tsv),
        (.[] | [(.priority | tostring), .cluster, .ns, .name,
                (.images | tostring), (.cves | tostring), (.fixable | tostring)] | @tsv)
    ' "$tmpdir"/*.json | column -t -s $'\t'
    rm -rf "$tmpdir"
}
