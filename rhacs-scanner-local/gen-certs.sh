#!/usr/bin/env bash
#
# Generate self-signed TLS certificates that StackRox Scanner V4 accepts.
#
# The scanner (release build) verifies peer certs against StackRox's own
# service-identity rules, NOT just CA trust. The verifier in
# pkg/clientconn/service_cert_fallback_verifier.go requires:
#
#   - CA Common Name == "StackRox Certificate Authority"
#   - server cert CN  == "<SERVICE_TYPE>: <Identifier>"  (e.g. "CENTRAL_SERVICE: Central")
#   - server cert OU  == "<SERVICE_TYPE>"                 (e.g. "CENTRAL_SERVICE")
#   - SAN matching the expected service hostname (central.stackrox)
#
# This script produces:
#   certs/ca.pem            - the CA cert (mounted into the scanner)
#   certs/ca-key.pem        - CA private key (kept for re-signing only)
#   certs/server-cert.pem   - "Central" identity cert (used by nginx vuln proxy)
#   certs/server-key.pem    - "Central" private key
#   certs/cert.pem          - scanner's own service cert (mounted into scanner)
#   certs/key.pem           - scanner's own private key

set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs
cd certs

# 1. CA — CN must be the exact StackRox CA name.
openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca.pem -days 3650 -nodes \
  -subj "/CN=StackRox Certificate Authority"

# 2. "Central" server cert — used by the nginx vuln proxy. The scanner connects
#    to it and verifies it as the Central service identity.
openssl req -newkey rsa:2048 -keyout server-key.pem -out server-req.pem -nodes \
  -subj "/CN=CENTRAL_SERVICE: Central/OU=CENTRAL_SERVICE" \
  -addext "subjectAltName=DNS:central.stackrox,DNS:central.stackrox.svc,DNS:central,DNS:localhost,IP:127.0.0.1"
openssl x509 -req -in server-req.pem -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -out server-cert.pem -days 3650 \
  -extfile <(echo "subjectAltName=DNS:central.stackrox,DNS:central.stackrox.svc,DNS:central,DNS:localhost,IP:127.0.0.1")

# 3. Scanner's own service cert — presented for its client cert / mTLS.
openssl req -newkey rsa:2048 -keyout key.pem -out scanner-req.pem -nodes \
  -subj "/CN=SCANNER_V4_SERVICE: Scanner/OU=SCANNER_V4_SERVICE" \
  -addext "subjectAltName=DNS:scanner-v4,DNS:localhost,IP:127.0.0.1"
openssl x509 -req -in scanner-req.pem -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -out cert.pem -days 3650 \
  -extfile <(echo "subjectAltName=DNS:scanner-v4,DNS:localhost,IP:127.0.0.1")

rm -f server-req.pem scanner-req.pem ca.srl

echo "Certs generated:"
openssl verify -CAfile ca.pem server-cert.pem
openssl verify -CAfile ca.pem cert.pem
