#!/usr/bin/env bash
#
# Download the Scanner V4 vulnerability bundle.
#
# Release-build scanners refuse outbound HTTP to anything except "Central",
# so they can never fetch this themselves in a standalone setup. We download
# it on the host and serve it locally via the nginx vuln proxy (see README).
#
# The bundle is ~240 MB. Re-run to refresh vulnerability data.

set -euo pipefail
cd "$(dirname "$0")"
mkdir -p vuln-data

URL="https://definitions.stackrox.io/v4/vulnerability-bundles/dev/vulnerabilities.zip"
OUT="vuln-data/vulnerabilities.zip"

echo "Downloading vuln bundle from ${URL} ..."
curl -fL --progress-bar -o "${OUT}" "${URL}"
echo "Saved $(du -h "${OUT}" | cut -f1) to ${OUT}"
