#!/usr/bin/env bash
#
# deploy.sh — Automate the full Scanner V4 local stack lifecycle.
#
# See README.md for architecture details. This script is idempotent:
# safe to run multiple times without destroying state.
#
# Usage:
#   ./deploy.sh                     # full setup + start
#   ./deploy.sh --refresh           # re-download vuln bundle then start
#   ./deploy.sh --build-scannerctl  # force rebuild scannerctl
#   ./deploy.sh --skip-scannerctl   # skip scannerctl build entirely
#   ./deploy.sh --no-wait           # don't wait for vuln import
#   ./deploy.sh --stackrox-src PATH # path to stackrox source tree
#   ./deploy.sh --down              # stop the stack
#   ./deploy.sh --status            # show current stack status
#   ./deploy.sh --help              # this message

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants & script directory
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

SCANNERCTL="$SCRIPT_DIR/scannerctl"
VULN_BUNDLE="$SCRIPT_DIR/vuln-data/vulnerabilities.zip"
VULN_BUNDLE_MIN_SIZE=100000000  # 100 MB — catch truncated downloads
CERT_FILES=(ca.pem ca-key.pem server-cert.pem server-key.pem cert.pem key.pem)
CONTAINERS=(scanner-v4-db vuln-server scanner-v4)
VULN_READY_MSG="all vulnerability bundles were updated at least once"
WAIT_TIMEOUT=1200  # 20 minutes in seconds

# ---------------------------------------------------------------------------
# Colors (only when stdout is a terminal)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' RESET=''
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()    { printf "${BLUE}[INFO]${RESET}  %s\n" "$*"; }
ok()      { printf "${GREEN}[OK]${RESET}    %s\n" "$*"; }
warn()    { printf "${YELLOW}[WARN]${RESET}  %s\n" "$*"; }
err()     { printf "${RED}[ERROR]${RESET} %s\n" "$*" >&2; }
step()    { printf "\n${BOLD}${CYAN}==> %s${RESET}\n" "$*"; }

die() {
    err "$@"
    exit 1
}

require_cmd() {
    if ! command -v "$1" &>/dev/null; then
        die "'$1' is required but not found in PATH."
    fi
}

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
FLAG_REFRESH=false
FLAG_BUILD_SCANNERCTL=false
FLAG_SKIP_SCANNERCTL=false
FLAG_NO_WAIT=false
FLAG_DOWN=false
FLAG_STATUS=false
STACKROX_SRC=""

usage() {
    printf "${BOLD}Usage:${RESET} %s [FLAGS]\n\n" "$(basename "$0")"
    cat <<'USAGE'
FLAGS:
  --refresh             Force re-download of vulnerability bundle
  --build-scannerctl    Force rebuild of scannerctl binary
  --skip-scannerctl     Skip scannerctl build entirely
  --no-wait             Don't wait for vuln import to complete
  --stackrox-src PATH   Path to stackrox source tree
  --down                Stop the stack (podman-compose down)
  --status              Show current stack status only
  --help                Show this help message
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --refresh)          FLAG_REFRESH=true; shift ;;
        --build-scannerctl) FLAG_BUILD_SCANNERCTL=true; shift ;;
        --skip-scannerctl)  FLAG_SKIP_SCANNERCTL=true; shift ;;
        --no-wait)          FLAG_NO_WAIT=true; shift ;;
        --down)             FLAG_DOWN=true; shift ;;
        --status)           FLAG_STATUS=true; shift ;;
        --stackrox-src)
            [[ $# -ge 2 ]] || die "--stackrox-src requires a path argument"
            STACKROX_SRC="$2"; shift 2 ;;
        --help|-h)          usage; exit 0 ;;
        *)                  die "Unknown flag: $1 (use --help for usage)" ;;
    esac
done

# ---------------------------------------------------------------------------
# --status: show stack status and exit
# ---------------------------------------------------------------------------
show_status() {
    step "Stack Status"
    local all_running=true
    for cname in "${CONTAINERS[@]}"; do
        local state
        state=$(podman inspect --format '{{.State.Status}}' "$cname" 2>/dev/null || echo "not found")
        if [[ "$state" == "running" ]]; then
            ok "$cname: running"
        else
            warn "$cname: $state"
            all_running=false
        fi
    done

    # Health check for DB
    local db_health
    db_health=$(podman inspect --format '{{.State.Health.Status}}' scanner-v4-db 2>/dev/null || echo "unknown")
    info "scanner-v4-db health: $db_health"

    # Port check
    for port in 8443 9443; do
        if podman port scanner-v4 "$port" &>/dev/null; then
            ok "Port $port is mapped"
        else
            warn "Port $port is not mapped"
        fi
    done

    # Scannerctl
    if [[ -x "$SCANNERCTL" ]]; then
        ok "scannerctl binary present at $SCANNERCTL"
    else
        info "scannerctl not found (optional)"
    fi

    # Certs
    local certs_ok=true
    for f in "${CERT_FILES[@]}"; do
        if [[ ! -f "$SCRIPT_DIR/certs/$f" ]]; then
            certs_ok=false
            break
        fi
    done
    if $certs_ok; then
        ok "TLS certificates present"
    else
        warn "TLS certificates incomplete — run ./gen-certs.sh"
    fi

    # Vuln bundle
    if [[ -f "$VULN_BUNDLE" ]]; then
        local sz
        sz=$(stat -f%z "$VULN_BUNDLE" 2>/dev/null || stat --format=%s "$VULN_BUNDLE" 2>/dev/null || echo 0)
        if [[ "$sz" -ge "$VULN_BUNDLE_MIN_SIZE" ]]; then
            ok "Vulnerability bundle present ($(du -h "$VULN_BUNDLE" | cut -f1))"
        else
            warn "Vulnerability bundle exists but looks truncated ($sz bytes)"
        fi
    else
        warn "Vulnerability bundle not downloaded"
    fi

    if $all_running; then
        printf "\n${GREEN}${BOLD}Stack is UP.${RESET}\n"
    else
        printf "\n${YELLOW}${BOLD}Stack is not fully running.${RESET}\n"
    fi
}

if $FLAG_STATUS; then
    show_status
    exit 0
fi

# ---------------------------------------------------------------------------
# --down: stop the stack and exit
# ---------------------------------------------------------------------------
if $FLAG_DOWN; then
    step "Stopping the stack"
    podman-compose down
    ok "Stack stopped."
    exit 0
fi

# =========================================================================
# FULL DEPLOY PATH
# =========================================================================

step "Checking dependencies"

# Required tools
for cmd in podman podman-compose openssl curl; do
    if command -v "$cmd" &>/dev/null; then
        ok "$cmd found"
    else
        if [[ "$cmd" == "podman-compose" ]]; then
            die "'podman-compose' not found. Install with: pip install podman-compose"
        else
            die "'$cmd' is required but not found in PATH."
        fi
    fi
done

# Optional: Go
GO_AVAILABLE=false
if command -v go &>/dev/null; then
    GO_VERSION=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | sed 's/go//')
    GO_MAJOR=$(echo "$GO_VERSION" | cut -d. -f1)
    GO_MINOR=$(echo "$GO_VERSION" | cut -d. -f2)
    if [[ "$GO_MAJOR" -ge 1 && "$GO_MINOR" -ge 21 ]]; then
        ok "Go $GO_VERSION found (>= 1.21)"
        GO_AVAILABLE=true
    else
        warn "Go $GO_VERSION found but < 1.21 — scannerctl build requires 1.21+"
    fi
else
    info "Go not found (optional — needed only for building scannerctl)"
fi

# ---------------------------------------------------------------------------
# Check podman machine (macOS only)
# ---------------------------------------------------------------------------
if [[ "$(uname -s)" == "Darwin" ]]; then
    step "Checking podman machine (macOS)"
    if podman machine info &>/dev/null; then
        # Check if at least one machine is running
        if podman info &>/dev/null; then
            ok "Podman machine is running"
        else
            die "Podman machine exists but is not running. Start it with: podman machine start"
        fi
    else
        die "No podman machine found. Create one with: podman machine init && podman machine start"
    fi
fi

# ---------------------------------------------------------------------------
# Check disk space (soft warning only)
# ---------------------------------------------------------------------------
step "Checking disk space"
DISK_WARNING=false
if [[ "$(uname -s)" == "Darwin" ]]; then
    # Try to check inside the podman VM
    VM_FREE_KB=$(podman machine ssh -- df -k /home 2>/dev/null | tail -1 | awk '{print $4}' || echo "")
    if [[ -n "$VM_FREE_KB" && "$VM_FREE_KB" =~ ^[0-9]+$ ]]; then
        VM_FREE_GB=$(( VM_FREE_KB / 1048576 ))
        if [[ "$VM_FREE_GB" -lt 3 ]]; then
            warn "Podman VM has ~${VM_FREE_GB}GB free — need ~3GB. Consider: podman system prune -a --volumes"
            DISK_WARNING=true
        else
            ok "Podman VM has ~${VM_FREE_GB}GB free"
        fi
    else
        info "Could not determine podman VM disk space — skipping check"
    fi
else
    # Linux: check local disk
    LOCAL_FREE_KB=$(df -k "$SCRIPT_DIR" | tail -1 | awk '{print $4}')
    if [[ -n "$LOCAL_FREE_KB" && "$LOCAL_FREE_KB" =~ ^[0-9]+$ ]]; then
        LOCAL_FREE_GB=$(( LOCAL_FREE_KB / 1048576 ))
        if [[ "$LOCAL_FREE_GB" -lt 3 ]]; then
            warn "Only ~${LOCAL_FREE_GB}GB free — need ~3GB. Consider: podman system prune -a --volumes"
            DISK_WARNING=true
        else
            ok "~${LOCAL_FREE_GB}GB free on disk"
        fi
    else
        info "Could not determine free disk space — skipping check"
    fi
fi

# ---------------------------------------------------------------------------
# Generate TLS certs
# ---------------------------------------------------------------------------
step "TLS certificates"
CERTS_OK=true
for f in "${CERT_FILES[@]}"; do
    if [[ ! -f "$SCRIPT_DIR/certs/$f" ]]; then
        CERTS_OK=false
        break
    fi
done

if $CERTS_OK; then
    ok "All certificate files already present in certs/"
else
    info "Generating TLS certificates..."
    bash "$SCRIPT_DIR/gen-certs.sh"
    # Verify
    for f in "${CERT_FILES[@]}"; do
        if [[ ! -f "$SCRIPT_DIR/certs/$f" ]]; then
            die "Certificate generation failed — missing certs/$f"
        fi
    done
    ok "Certificates generated successfully"
fi

# ---------------------------------------------------------------------------
# Fetch vulnerability bundle
# ---------------------------------------------------------------------------
step "Vulnerability bundle"
NEED_FETCH=false

if $FLAG_REFRESH; then
    info "Refresh requested — will re-download"
    NEED_FETCH=true
elif [[ ! -f "$VULN_BUNDLE" ]]; then
    info "Bundle not found — downloading"
    NEED_FETCH=true
else
    # Check size to catch truncated downloads
    BUNDLE_SIZE=$(stat -f%z "$VULN_BUNDLE" 2>/dev/null || stat --format=%s "$VULN_BUNDLE" 2>/dev/null || echo 0)
    if [[ "$BUNDLE_SIZE" -lt "$VULN_BUNDLE_MIN_SIZE" ]]; then
        warn "Bundle looks truncated ($BUNDLE_SIZE bytes) — re-downloading"
        NEED_FETCH=true
    else
        ok "Vulnerability bundle present ($(du -h "$VULN_BUNDLE" | cut -f1))"
    fi
fi

if $NEED_FETCH; then
    info "Downloading vulnerability bundle (~240 MB)..."
    bash "$SCRIPT_DIR/fetch-vuln-bundle.sh"
    if [[ ! -f "$VULN_BUNDLE" ]]; then
        die "Download failed — $VULN_BUNDLE not created"
    fi
    BUNDLE_SIZE=$(stat -f%z "$VULN_BUNDLE" 2>/dev/null || stat --format=%s "$VULN_BUNDLE" 2>/dev/null || echo 0)
    if [[ "$BUNDLE_SIZE" -lt "$VULN_BUNDLE_MIN_SIZE" ]]; then
        die "Download appears truncated ($BUNDLE_SIZE bytes). Check network and retry."
    fi
    ok "Bundle downloaded ($(du -h "$VULN_BUNDLE" | cut -f1))"
fi

# ---------------------------------------------------------------------------
# Build scannerctl (optional)
# ---------------------------------------------------------------------------
step "scannerctl"

NEED_BUILD=false
if $FLAG_SKIP_SCANNERCTL; then
    info "Skipping scannerctl build (--skip-scannerctl)"
elif $FLAG_BUILD_SCANNERCTL; then
    info "Rebuild requested (--build-scannerctl)"
    NEED_BUILD=true
elif [[ -x "$SCANNERCTL" ]]; then
    ok "scannerctl binary already present"
else
    info "scannerctl not found — will attempt to build"
    NEED_BUILD=true
fi

if $NEED_BUILD; then
    if ! $GO_AVAILABLE; then
        warn "Go 1.21+ not available — skipping scannerctl build."
        warn "scannerctl is optional for the stack; install Go to build it later."
    else
        # Determine stackrox source path
        SRC_PATH=""
        if [[ -n "$STACKROX_SRC" ]]; then
            SRC_PATH="$STACKROX_SRC"
        elif [[ -d "$HOME/src/stackrox/scanner" ]]; then
            SRC_PATH="$HOME/src/stackrox"
        elif [[ -d "$HOME/stackrox/scanner" ]]; then
            SRC_PATH="$HOME/stackrox"
        elif [[ -t 0 ]]; then
            # Interactive — ask the user
            printf "${CYAN}Enter path to stackrox source tree (or press Enter to skip): ${RESET}"
            read -r user_path
            if [[ -n "$user_path" && -d "$user_path/scanner" ]]; then
                SRC_PATH="$user_path"
            elif [[ -n "$user_path" ]]; then
                warn "Directory '$user_path/scanner' not found — skipping build"
            fi
        fi

        if [[ -n "$SRC_PATH" && -d "$SRC_PATH/scanner" ]]; then
            info "Building scannerctl from $SRC_PATH/scanner ..."
            (
                cd "$SRC_PATH/scanner"
                go build -o "$SCANNERCTL" ./cmd/scannerctl/
            )
            if [[ -x "$SCANNERCTL" ]]; then
                ok "scannerctl built successfully"
            else
                warn "scannerctl build produced no executable — continuing without it"
            fi
        else
            warn "stackrox source tree not found — skipping scannerctl build."
            warn "To build later: cd <stackrox>/scanner && go build -o $SCANNERCTL ./cmd/scannerctl/"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Start the stack
# ---------------------------------------------------------------------------
step "Starting the stack"

# Check if containers are already running
ALL_RUNNING=true
for cname in "${CONTAINERS[@]}"; do
    cstate=$(podman inspect --format '{{.State.Status}}' "$cname" 2>/dev/null || echo "not found")
    if [[ "$cstate" != "running" ]]; then
        ALL_RUNNING=false
        break
    fi
done

if $ALL_RUNNING; then
    ok "All containers already running"
else
    info "Running podman-compose up -d ..."
    podman-compose up -d
    ok "Containers started"
fi

# Wait for DB healthcheck
info "Waiting for scanner-v4-db to become healthy..."
DB_WAIT=0
DB_TIMEOUT=120
while [[ $DB_WAIT -lt $DB_TIMEOUT ]]; do
    db_health=$(podman inspect --format '{{.State.Health.Status}}' scanner-v4-db 2>/dev/null || echo "unknown")
    if [[ "$db_health" == "healthy" ]]; then
        break
    fi
    sleep 3
    DB_WAIT=$(( DB_WAIT + 3 ))
    printf "\r  DB health: %-12s (%ds elapsed)" "$db_health" "$DB_WAIT"
done
printf "\n"

if [[ "$db_health" == "healthy" ]]; then
    ok "scanner-v4-db is healthy"
else
    warn "scanner-v4-db health is '$db_health' after ${DB_TIMEOUT}s — continuing anyway"
fi

# ---------------------------------------------------------------------------
# Wait for vuln import
# ---------------------------------------------------------------------------
if ! $FLAG_NO_WAIT; then
    step "Waiting for vulnerability import"
    info "Monitoring scanner-v4 logs for import completion..."
    info "(This takes 8-12 minutes on a first run. Subsequent starts are near-instant.)"

    WAIT_ELAPSED=0
    IMPORT_DONE=false

    while [[ $WAIT_ELAPSED -lt $WAIT_TIMEOUT ]]; do
        # Check container is still running
        scanner_state=$(podman inspect --format '{{.State.Status}}' scanner-v4 2>/dev/null || echo "not found")
        if [[ "$scanner_state" != "running" ]]; then
            err "scanner-v4 container is not running (state: $scanner_state)"
            err "Check logs with: podman logs scanner-v4"
            break
        fi

        # Check if the ready message has appeared in logs.
        # podman logs includes the full log history for the current container
        # instance, so on a warm restart (persisted volume) this line will
        # appear immediately once the scanner re-emits it.
        #
        # IMPORTANT: grep -q exits early on match, closing the pipe. Under
        # pipefail, podman logs then gets SIGPIPE (exit 141) which makes
        # the whole pipeline non-zero even though grep succeeded. We
        # disable pipefail in a subshell to avoid this.
        if (set +o pipefail; podman logs scanner-v4 2>&1 | grep -q "$VULN_READY_MSG"); then
            IMPORT_DONE=true
            break
        fi

        sleep 10
        WAIT_ELAPSED=$(( WAIT_ELAPSED + 10 ))
        MINS=$(( WAIT_ELAPSED / 60 ))
        SECS=$(( WAIT_ELAPSED % 60 ))
        printf "\r  Elapsed: %dm%02ds / %dm timeout" "$MINS" "$SECS" "$(( WAIT_TIMEOUT / 60 ))"
    done
    printf "\n"

    if $IMPORT_DONE; then
        ok "Vulnerability data is loaded and scanner is ready"
    else
        if [[ $WAIT_ELAPSED -ge $WAIT_TIMEOUT ]]; then
            warn "Timed out after $(( WAIT_TIMEOUT / 60 )) minutes waiting for vuln import."
            warn "The import may still be running. Check with: podman logs -f scanner-v4"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
step "Verification"

VERIFY_PASS=true

# Check all 3 containers
for cname in "${CONTAINERS[@]}"; do
    cstate=$(podman inspect --format '{{.State.Status}}' "$cname" 2>/dev/null || echo "not found")
    if [[ "$cstate" == "running" ]]; then
        ok "$cname is running"
    else
        err "$cname is NOT running (state: $cstate)"
        VERIFY_PASS=false
    fi
done

# Check ports
for port in 8443 9443; do
    if podman port scanner-v4 "$port" &>/dev/null; then
        ok "Port $port is mapped ($(podman port scanner-v4 "$port" 2>/dev/null))"
    else
        warn "Port $port mapping not found"
        VERIFY_PASS=false
    fi
done

# Quick test scan if scannerctl is available and we waited for import
if [[ -x "$SCANNERCTL" ]] && ! $FLAG_NO_WAIT; then
    info "Running a quick test scan with scannerctl..."
    TEST_OUTPUT=""
    if TEST_OUTPUT=$(timeout 60 "$SCANNERCTL" scan \
        --indexer-address localhost:8443 \
        --matcher-address localhost:8443 \
        --insecure-skip-tls-verify \
        https://registry.hub.docker.com/library/alpine:latest 2>&1); then
        if echo "$TEST_OUTPUT" | grep -q '"name"' 2>/dev/null; then
            CVE_COUNT=$(echo "$TEST_OUTPUT" | grep -c '"name"' || true)
            ok "Test scan succeeded (alpine:latest — $CVE_COUNT vulnerability entries)"
        else
            ok "Test scan completed (no vulnerabilities found for alpine:latest — expected for minimal image)"
        fi
    else
        warn "Test scan did not succeed — scanner may still be initializing"
        warn "Try manually: ./scannerctl scan https://registry.hub.docker.com/library/nginx:latest --indexer-address localhost:8443 --matcher-address localhost:8443 --insecure-skip-tls-verify"
    fi
elif [[ -x "$SCANNERCTL" ]]; then
    info "scannerctl available but --no-wait was set — skipping test scan"
else
    info "scannerctl not available — skipping test scan"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
step "Summary"
printf "\n"
if $VERIFY_PASS; then
    printf "  ${GREEN}${BOLD}Scanner V4 stack is UP and running.${RESET}\n"
else
    printf "  ${YELLOW}${BOLD}Stack started with warnings — check messages above.${RESET}\n"
fi
printf "\n"
printf "  ${BOLD}gRPC endpoint:${RESET}    localhost:8443\n"
printf "  ${BOLD}HTTP endpoint:${RESET}    localhost:9443\n"
printf "  ${BOLD}Compose file:${RESET}     %s/podman-compose.yml\n" "$SCRIPT_DIR"
if [[ -x "$SCANNERCTL" ]]; then
    printf "  ${BOLD}scannerctl:${RESET}       %s\n" "$SCANNERCTL"
fi
printf "\n"
printf "  ${BOLD}Useful commands:${RESET}\n"
printf "    podman logs -f scanner-v4     # watch scanner logs\n"
printf "    ./deploy.sh --status          # check stack status\n"
printf "    ./deploy.sh --down            # stop the stack\n"
if [[ -x "$SCANNERCTL" ]]; then
    printf "    ./scannerctl scan https://registry.hub.docker.com/library/nginx:latest \\\\\n"
    printf "      --indexer-address localhost:8443 --matcher-address localhost:8443 \\\\\n"
    printf "      --insecure-skip-tls-verify\n"
fi
printf "\n"
