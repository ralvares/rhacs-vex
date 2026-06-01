# Standalone StackRox / RHACS Scanner V4 (Podman)

Run the Red Hat Advanced Cluster Security (RHACS) **Scanner V4** locally with
Podman — no OpenShift, no Central, no full ACS deployment. Just the scanner,
its database, and a small proxy to feed it vulnerability data.

Scanner V4 is the ClairCore-based scanner used by RHACS 4.x. It indexes
container image layers (OS packages **and** language dependencies — Go, Java,
Node, Python, Ruby, …) and matches them against an upstream vulnerability feed.

This stack pins everything to **4.10.2** to match the RHACS 4.10.2 release. Bump
the image tags and re-fetch the vuln bundle to track a different RHACS version.

**This directory is fully self-contained** (`~/rhacs-vex/rhacs-scanner-local`).
It has no dependency on the StackRox source tree at runtime. The source is only
borrowed once, to compile the `scannerctl` CLI (see
[Build `scannerctl`](#build-scannerctl-the-scan-cli)) — keep that clone
elsewhere so local config never lands in the StackRox git repo.

---

## Why this is more involved than `podman run`

The published scanner images are **release builds**, which carry two
restrictions designed for the "scanner runs next to Central inside a cluster"
deployment model:

1. **Outbound HTTP is denied.** The matcher's HTTP transport blocks every
   request whose hostname is not the configured Central endpoint. It can
   therefore never reach `definitions.stackrox.io` to download vulnerability
   data on its own. (Source: `scanner/internal/httputil/transport_deny.go` +
   `transport_mux.go`.)

2. **TLS peer verification is StackRox-specific.** The scanner verifies the
   server it talks to as a StackRox *service identity*, not via ordinary CA
   trust. The CA must be named `StackRox Certificate Authority` and the server
   cert must carry the Central service CN/OU. (Source:
   `pkg/clientconn/service_cert_fallback_verifier.go`.)

**The workaround:** download the vuln bundle on the host, then serve it from a
local **nginx** container that impersonates Central — it listens on the
hostname `central`, presents a cert with the Central service identity, and the
scanner happily pulls "its" vulnerability data from it. No code changes, stock
images.

```
                            scanner-net (podman bridge)
  ┌──────────────┐        ┌───────────────────────────┐        ┌──────────────┐
  │  scannerctl  │ gRPC   │         scanner-v4         │  TLS   │ vuln-server  │
  │   (host)     │──8443─▶│  indexer + matcher (1 proc)│──443──▶│   (nginx,    │
  └──────────────┘        │                            │  as    │  alias:      │
                          │                            │ Central│  "central")  │
                          └─────────────┬──────────────┘        └──────┬───────┘
                                        │ 5432                         │ serves
                                        ▼                              ▼
                                ┌──────────────┐              vuln-data/
                                │ scanner-v4-db│              vulnerabilities.zip
                                │ (PostgreSQL) │
                                └──────────────┘
```

---

## Prerequisites

- **Podman** + **podman-compose** (`pip install podman-compose` or your package
  manager). `podman machine` must be running on macOS.
- **~3 GB free** in the Podman VM (images ~660 MB, vuln DB grows the Postgres
  volume to ~1.5 GB after import). Check with `podman system df`; reclaim with
  `podman system prune -a --volumes`.
- **openssl** (cert generation), **curl** (bundle download).
- **Go 1.21+** — only needed to build `scannerctl`, the scan CLI. Optional if
  you drive the gRPC API another way.
- Network access to `quay.io` (images) and `definitions.stackrox.io` (vuln
  bundle). Both are public — no Red Hat subscription required.

> Using `registry.redhat.io/advanced-cluster-security/rhacs-scanner-v4-rhel8`
> instead of the quay.io images? Those need a Red Hat pull secret
> (`podman login registry.redhat.io`). The quay.io upstream images are
> byte-identical in behavior and need no auth.

---

## Files in this directory

| File                  | What it is                                                        |
|-----------------------|-------------------------------------------------------------------|
| `podman-compose.yml`  | The three services: DB, vuln proxy, scanner.                      |
| `scanner-config.yaml` | Scanner config — indexer + matcher in one process.                |
| `postgresql.conf`     | Postgres config the StackRox DB image expects to be mounted.      |
| `nginx.conf`          | Vuln proxy: serves the bundle at Central's definitions endpoint.  |
| `gen-certs.sh`        | Generates StackRox-compatible TLS certs into `certs/`.            |
| `fetch-vuln-bundle.sh`| Downloads the vuln bundle into `vuln-data/`.                       |
| `certs/`              | Generated TLS material (created by `gen-certs.sh`). **Private keys** — gitignored. |
| `vuln-data/`          | The downloaded `vulnerabilities.zip` (~240 MB). Gitignored.       |
| `scannerctl`          | Built scan CLI (created in the build step below, ~150 MB). Gitignored. |
| `.gitignore`          | Excludes the three regenerable/secret artifacts above.            |

The three large/secret items — `scannerctl`, `vuln-data/`, `certs/` — are
**regenerable build artifacts**, excluded by `.gitignore`. If you clone or copy
this directory and they're missing, recreate them:

```bash
./gen-certs.sh           # → certs/
./fetch-vuln-bundle.sh   # → vuln-data/vulnerabilities.zip
# rebuild scannerctl: see "Build scannerctl" below
```

This keeps the committable part of the directory tiny (configs + scripts +
this README) and free of secrets.

---

## Setup from scratch

```bash
cd ~/rhacs-vex/rhacs-scanner-local

# 1. Generate TLS certs (CA + Central identity + scanner identity)
./gen-certs.sh

# 2. Download the vulnerability bundle (~240 MB)
./fetch-vuln-bundle.sh

# 3. Start the stack
podman-compose up -d

# 4. Watch the first-run vuln import (takes ~10 min — see note below)
podman logs -f scanner-v4
```

On the **first** start the matcher pulls every vulnerability bundle from the
local proxy and imports it into Postgres. This is heavy: the RHEL VEX bundle
alone is ~3 million records, total import is **8–12 minutes** on a laptop. Watch
for this line — it means the scanner is ready:

```
... "message":"all vulnerability bundles were updated at least once: setting to initialized"
```

The data persists in the `scanner-v4-data` volume, so subsequent restarts skip
the import and are ready in seconds.

### Build `scannerctl` (the scan CLI)

`scannerctl` is **not** shipped inside the scanner container image — you build
it yourself from the StackRox source tree. It's a Go binary under
`scanner/cmd/scannerctl/` in the `stackrox/stackrox` repo.

**The source clone is needed _only_ to produce this one binary.** Nothing else
in this directory depends on it — once `scannerctl` is built and copied here,
the clone can live anywhere or be deleted. Keep the source and this standalone
setup separate so you never commit local podman/config files into the StackRox
git tree.

```bash
# 1. Clone the source somewhere OUTSIDE this directory (skip if you already have it)
git clone https://github.com/stackrox/stackrox ~/src/stackrox
cd ~/src/stackrox
git checkout 4.10.2          # match the image tags; omit to build from main

# 2. Build scannerctl and drop the binary into this setup directory
cd scanner
go build -o ~/rhacs-vex/rhacs-scanner-local/scannerctl ./cmd/scannerctl/
```

Verify:

```bash
~/rhacs-vex/rhacs-scanner-local/scannerctl --help
```

That writes the self-contained `scannerctl` binary (~150 MB) into this
directory. After this, the `~/src/stackrox` clone is no longer required at
runtime.

> Module path is `github.com/stackrox/rox`; `scannerctl`'s `main` package is at
> `scanner/cmd/scannerctl/`. The build pulls dependencies via Go modules, so the
> first build needs network access and takes a minute or two. The compiled CLI
> only needs to speak the gRPC API of the running 4.10.2 images — any reasonably
> recent checkout works, but checking out the matching `4.10.2` tag avoids
> surprises.
>
> Already have the repo checked out elsewhere (e.g. `~/stackrox`)? Just build
> from there: `cd <your-clone>/scanner && go build -o
> ~/rhacs-vex/rhacs-scanner-local/scannerctl ./cmd/scannerctl/`.

---

## Scanning an image

`scannerctl` expects the image reference as an `http(s)://` URL.

```bash
cd ~/rhacs-vex/rhacs-scanner-local

./scannerctl scan https://registry.hub.docker.com/library/nginx:latest \
  --indexer-address localhost:8443 \
  --matcher-address localhost:8443 \
  --insecure-skip-tls-verify
```

Output is a JSON vulnerability report: per-CVE id, description, severity,
CVSS v2/v3 vectors, EPSS probability, and `fixed_in_version` where known.

Useful flags:

- `--index-only` — index the image and emit the package/file index report
  without matching CVEs.
- `--digest <sha256:...>` — pin a specific image digest.
- `ROX_SCANNERCTL_BASIC_AUTH=user:pass` (env) — registry credentials for
  private images.

Scan a private registry image:

```bash
ROX_SCANNERCTL_BASIC_AUTH='myuser:mytoken' \
./scannerctl scan https://myregistry.example.com/team/app:1.2.3 \
  --indexer-address localhost:8443 \
  --matcher-address localhost:8443 \
  --insecure-skip-tls-verify
```

### Generating an SBOM

The scanner produces an **SPDX 2.3** software bill of materials from the same
index it uses for vulnerability matching. If the image was already scanned, the
SBOM is generated instantly from the cached index; otherwise it indexes first.

```bash
cd ~/rhacs-vex/rhacs-scanner-local

./scannerctl sbom https://registry.hub.docker.com/library/nginx:latest \
  --indexer-address localhost:8443 \
  --matcher-address localhost:8443 \
  --insecure-skip-tls-verify > nginx-sbom.json
```

Output is SPDX 2.3 JSON: every package with name, version, the file it was
found in (e.g. `var/lib/dpkg/status`), and `primaryPackagePurpose`
(SOURCE / APPLICATION). The `creationInfo.creators` field records the scanner
and ClairCore versions. Example: `nginx:latest` yields ~269 packages.

Flags:
- `--skip-indexing` — fail instead of indexing if no existing index report is
  found (use after a prior `scan`/`sbom` of the same image).
- `--digest <sha256:...>` — pin a specific image digest.
- `ROX_SCANNERCTL_BASIC_AUTH=user:pass` (env) — credentials for private images.

gRPC equivalent: `Matcher.GetSBOM(index_report)`.

**One index, three outputs** — all driven from a single image indexing pass:

| Command                  | Output                                            |
|--------------------------|---------------------------------------------------|
| `scannerctl scan`        | CVE report (severity, CVSS v2/v3, EPSS, fixes)    |
| `scannerctl sbom`        | SPDX 2.3 package inventory                         |
| `scannerctl scan --index-only` | raw package/file index report               |

### Driving the gRPC API directly

Port `8443` exposes the Indexer and Matcher gRPC services (TLS):

- `Indexer.CreateIndexReport(image_ref)` → package/file index
- `Indexer.GetOrCreateIndexReport(...)` → idempotent index
- `Matcher.GetVulnerabilities(index_report)` → matched CVEs
- `Matcher.GetSBOM(index_report)` → SBOM
- `Matcher.GetMetadata()` → last vuln DB update time

Anonymous auth is enabled (`ROX_SCANNER_V4_ALLOW_ANONYMOUS_AUTH=true`), so no
client cert is required from callers.

---

## VEX triage with this scanner

The parent directory's triage tooling can use this stack as its scanner backend —
producing RHACS-identical false-positive/positive verdicts with no Central:

```bash
cd ..   # ~/rhacs-vex

# single image
python3 triage_clairv4.py --image registry.redhat.io/.../rhacs-main-rhel8:4.10.2 \
  --pull-secret ~/pullsecret.txt

# all operators in an OCP catalog
python3 triage_operators_clairv4.py --version 4.21 --pull-secret ~/pullsecret.txt

# full pipeline (catalogs + OCP release + operators)
python3 setup_and_scan.py --scanner clairv4 --pull-secret ~/pullsecret.txt
```

`triage_clairv4.py` drives `scannerctl` against this stack (default
`localhost:8443`), flattens the VulnerabilityReport, and feeds it to the shared VEX
engine. It auto-locates `scannerctl` here (`./rhacs-scanner-local/scannerctl`).

---

## Operations

```bash
# Status
podman ps

# Logs
podman logs -f scanner-v4
podman logs scanner-v4-db
podman logs vuln-server

# Stop (keeps the vuln DB volume)
podman-compose down

# Stop and wipe everything, including the imported vuln DB
podman-compose down -v

# Refresh vulnerability data (re-download + re-import)
./fetch-vuln-bundle.sh
podman restart scanner-v4        # re-imports changed bundles
```

---

## How the pieces fit (config reference)

**`scanner-config.yaml`**
- `stackrox_services: true` — required. Lifts the outbound-HTTP deny so the
  matcher can reach the (fake) Central. Also set as env
  `SCANNER_V4_STACKROX_SERVICES=true` for belt-and-suspenders.
- `indexer.enable` + `matcher.enable` — both `true`: one process does both.
- `matcher.indexer_addr: ""` — empty, so the matcher uses the in-process
  indexer instead of dialing a remote one over mTLS.
- `matcher.vulnerabilities_url: https://central/api/extensions/scannerdefinitions?version=ROX_VERSION`
  — points at the nginx proxy. Hostname `central` matches `ROX_CENTRAL_ENDPOINT`,
  so the request is routed through the (now-allowed) Central transport.
- DB connection uses `sslmode=disable` — plain TCP to Postgres on the internal
  bridge network.

**`podman-compose.yml` — scanner env**
- `ROX_SCANNER_V4_ALLOW_ANONYMOUS_AUTH=true` — lets `scannerctl` call gRPC
  without a Central-issued client cert.
- `SCANNER_V4_STACKROX_SERVICES=true` — see above.
- `ROX_CENTRAL_ENDPOINT=central:443` — defines which hostname counts as
  "Central" for transport routing **and** TLS identity verification.

**`nginx.conf`** — serves `vuln-data/vulnerabilities.zip` at
`/api/extensions/scannerdefinitions` over TLS, using the Central-identity cert
from `gen-certs.sh`.

**`postgresql.conf`** — the `scanner-v4-db` image's CMD is
`postgres -c config_file=/etc/stackrox.d/config/postgresql.conf`; that path is
normally injected by the Helm chart, so we mount our own.
- `default_text_search_config` **must be schema-qualified** (`pg_catalog.english`),
  not a bare `english`/`pg_simple`. The matcher runs full-text-search queries; an
  invalid value makes some `GetVulnerabilities` calls fail at query time with
  `invalid value for parameter "default_text_search_config"` — and only on the code
  paths that use FTS, so it can look like an intermittent per-image scan failure.

---

## Troubleshooting

**`scanner-v4-db` exits with `could not access the server configuration file`**
The image needs `postgresql.conf` mounted at
`/etc/stackrox.d/config/postgresql.conf`. The compose file already does this —
make sure `postgresql.conf` exists in this directory.

**Scanner logs `HTTP traffic denied` fetching the vuln bundle**
`stackrox_services` is not enabled, or the vuln URL hostname doesn't match
`ROX_CENTRAL_ENDPOINT`. Both must agree on `central`.

**`x509: certificate signed by unknown authority`**
Certs not generated by `gen-certs.sh`, or the CA CN is wrong. Re-run
`./gen-certs.sh` and `podman-compose down && podman-compose up -d`.

**`x509: certificate is valid for ..., not central.stackrox`**
The Central server cert is missing the `central.stackrox` SAN. Re-run
`gen-certs.sh` (it includes all required SANs) and restart.

**`matcher error: ... invalid value for parameter "default_text_search_config"`**
`postgresql.conf` has a bad `default_text_search_config`. It must be
schema-qualified — `pg_catalog.english`. Fix it, then
`podman restart scanner-v4-db scanner-v4`. Symptom is intermittent: only scans that
exercise full-text-search matchers fail, so some images scan fine and others error.

**`no space left on device` while pulling**
The Podman VM disk is full. `podman system df` to inspect,
`podman system prune -a --volumes` to reclaim.

**Scans hang or the matcher returns no CVEs**
The first-run vuln import may still be running. Wait for the
`setting to initialized` log line before scanning.

---

## Security notes

- The Postgres password (`scanner123`) and the self-signed certs are for
  **local development only**. Don't expose ports `8443`/`9443` beyond
  localhost.
- `--insecure-skip-tls-verify` on `scannerctl` skips verifying the scanner's
  own TLS cert — fine locally, not for anything shared.
- The vuln bundle is dev-channel data from `definitions.stackrox.io`. For
  production accuracy, use the RHACS-managed feed via a real Central.
