# Technical Explainer: Automated VEX Triage & Verification Framework

This document outlines the technical architecture and logic behind the automated VEX (Vulnerability Exploitability eXchange) triage process used to validate security findings from Red Hat Advanced Cluster Security (RHACS).

---

## 1. Executive Summary
The primary challenge in vulnerability management is distinguishing between a **technical presence** (the code exists in the image) and a **genuine risk** (the code is exploitable and unpatched). 

Our framework automates this distinction by cross-referencing three authoritative data layers:
1.  **RHACS Findings:** The raw scan results (Package + CVE).
2.  **Red Hat VEX (CSAF):** The vendor's authoritative statement on vulnerability status.
3.  **SPDX SBOM:** The physical proof of package lineage and relationships.

The result is a high-integrity triage process that eliminates false positives with zero manual intervention.

---

## 2. The Bridge: Binary-to-Source Mapping
### The Problem
Security scanners like RHACS report **Binary RPMs** (e.g., `python3-urllib3`). However, Red Hat publishes security advisories (VEX) against the **Source RPM** (e.g., `python-urllib3`). One source RPM can generate dozens of binary packages. A simple name-match search would fail to find the relevant security data.

### The Solution: SBOM Lineage
We use the **SPDX 2.3 SBOM** extracted directly from RHACS. The triage engine parses the `GENERATED_FROM` relationship within the SBOM:
* **Logic:** If the SBOM proves that `Binary-Package-A` was built from `Source-Package-B`, the engine automatically queries the VEX database for both names.
* **Impact:** This ensures 100% coverage of CVEs, even when the scanner and the advisory use different naming conventions.

---

## 3. The Precision Layer: Stream-Aware Auditing
Red Hat Enterprise Linux (RHEL) utilizes "Backporting"—fixing bugs in older versions without incrementing the major version number. This makes traditional "version A > version B" logic unreliable.

### Minor Stream Isolation (`elN_M`)
The engine detects the specific RHEL minor stream (e.g., RHEL 8.10 vs. RHEL 9.4) from the image labels and package metadata.
* **Logic:** It ensures that an installed package is only compared against fixes released for its **specific minor stream**.
* **Impact:** Prevents "False Negatives" where a fix in a newer release (e.g., 9.4) is incorrectly assumed to have protected an older release (e.g., 9.2).

### Module Stream Guarding
RHEL supports parallel software versions via "Module Streams" (e.g., `nodejs:18` and `nodejs:20`). 
* **The Check:** The engine identifies module-stream packages by the `+module+` string in their version release.
* **The Logic:** It matches these packages exclusively against VEX Product IDs containing the `::module:stream` suffix.
* **Impact:** Ensures that security fixes for one stream do not incorrectly clear vulnerabilities in a different stream.

---

## 4. Contextual Scoping: Identifying the Product
A single CVE might affect a package in RHEL, but the same package might be "Not Affected" when used within **OpenShift (OCP)** or a specific **Operator**.

The engine builds a `WorkloadContext` for every image using:
1.  **Registry Path:** Detects if it's a Base UBI, OCP component, or Operator.
2.  **Image Labels:** Extracts CPE (Common Platform Enumeration) strings to identify the exact product version (e.g., OCP 4.18).
3.  **VEX Scope Filtering:** The engine only applies "Not Affected" or "Fixed" statements if they are explicitly scoped to the detected product in the VEX document.

---

## 5. Automated Product Scoping: The Catalog-to-Namespace Map
For Red Hat Operators, identifying which VEX "Product ID" applies to an image is complex. A single registry namespace (e.g., `rhacm2`) might contain dozens of different images, each mapped to different product names in the VEX database.

To solve this, the engine uses an automated mapping file: **`data/ns_vex_prefixes.json`**.

### How it Works
1.  **Catalog Harvesting:** The `build_ns_map.py` script pre-processes Red Hat OLM (Operator Lifecycle Manager) catalogs. It inspects every operator bundle to extract the **Registry Namespace**, the **OLM Package Name**, and the **Operator Display Name**.
2.  **Normalization:** These names are normalized into "VEX-prefix candidates" (e.g., *"Advanced Cluster Security"* becomes `advanced_cluster_security`).
3.  **Dynamic Scoping:** At runtime, when the triage engine identifies an image's registry namespace (e.g., `rhacm2`), it automatically loads all associated product prefixes from this map.
4.  **Impact:** This allows the engine to automatically "know" that a CVE advisory for the product `advanced_cluster_management` is relevant to an image found in the `rhacm2` namespace. This eliminates the need for manual product-to-image lookups and ensures that Operator security data is scoped with surgical precision.

---

## 6. Non-RPM Logic (Go, npm, Python)
For bundled binaries (Go, npm) where version comparison is difficult, the engine uses **Product ID (PID) Membership**.
* **The Check:** Does the VEX document explicitly list this specific image (by its SHA256 digest) as "Fixed" or "Known Not Affected"?
* **The Logic:** If the Vendor has signed off on the image hash, the finding is cleared regardless of version string complexity.

---

## 6. Integrity Verification (The Sanity Check)
To ensure the triage results are never based on stale data, the engine performs a final **SBOM Consistency Check**:
* **Validation:** Every package name and version used to reach a "False Positive" verdict is cross-referenced against the live SBOM.
* **Outcome:** If the version in the scan result doesn't match the version physically present in the SBOM, the tool flags a **MISMATCH** for manual review.

---

## 7. Conclusion
By combining **physical lineage** (SBOM), **minor stream isolation** (RPM math), and **vendor authority** (VEX), we move from "best-guess" triage to **provable security integrity**. Every decision is backed by a specific relationship or version comparison that is 100% auditable.
