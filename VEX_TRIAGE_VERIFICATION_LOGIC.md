This document provides a technical breakdown of the automated security checks performed by the `triage.py` engine. It is designed to be used as a technical reference or as the basis for a security architecture presentation.

# **Title:** RHACS VEX Triage: Technical Integrity & Verification Framework

---

## **1. Overview**
The primary goal of this framework is to automate the decision-making process for Vulnerability Management. It determines if a CVE finding reported by a scanner (RHACS) is a **Genuine Positive** (Action Required) or a **False Positive** (No Risk).

The system achieves this by cross-referencing three distinct data layers:
1.  **Scanner Findings:** What the tool *thinks* is in the container.
2.  **Red Hat VEX (CSAF):** What the Vendor *authoritatively states* about the vulnerability.
3.  **SPDX SBOM:** The *physical proof* of package lineage and versioning within the image.

---

## **2. The Translation Layer: Binary-to-Source Mapping**
### **The Problem**
Scanners report **Binary RPMs** (e.g., `python3-urllib3`). However, security advisories are often published against the **Source RPM** (e.g., `python-urllib3`). Without a translation layer, automation fails because names do not match.

### **The Check**
The script parses the **SPDX SBOM** specifically looking for the `GENERATED_FROM` relationship.
* **Logic:** If `Package-A` (Binary) is `GENERATED_FROM` `Package-B` (Source), the triage engine automatically queries the VEX database for both names.
* **Outcome:** This ensures that vulnerabilities tracked under the "Source" name are correctly applied to the "Binary" package installed in the image.

---

## **3. The Triage Layer: Stream-Aware Auditing**
Red Hat Enterprise Linux (RHEL) uses "Backporting," meaning they fix security bugs in older versions of software without changing the major version number. A simple "is version A higher than version B" check is insufficient.

### **Minor Stream Isolation (`elN_M`)**
* **The Check:** The script uses `_detect_rhel_minor` to extract stream markers (e.g., `.el8_10` or `.el9_4`).
* **Logic:** It ensures that an installed package in the RHEL 9.2 stream is only compared against fixes released for the 9.2 stream. 
* **Outcome:** This prevents "False Negatives" where a fix in a newer minor release (9.4) is incorrectly assumed to have fixed an older release (9.2).

### **Module Stream Guarding**
* **The Check:** The script identifies if a package was installed via a "Module Stream" by looking for the `+module+` string in the version release.
* **Logic:** It matches these packages against VEX Product IDs containing the `::module:stream` suffix.
* **Outcome:** This ensures that "Base" system packages are never cleared by security advisories meant only for "Modular" versions of the same software.

---

## **4. The Non-RPM Logic (Go, npm, Python)**
For non-RPM components, version strings are often inconsistent and difficult to compare mathematically.

### **Contextual Scoping**
* **The Check:** Instead of comparing version numbers, the script checks for **Product ID (PID) Membership**.
* **Logic:** It asks: "Has the vendor explicitly listed this specific OpenShift or Operator image (by SHA/Digest) as 'Fixed' or 'Not Affected' in the VEX document?"
* **Outcome:** Provides 100% accuracy for bundled binaries where traditional version math would be unreliable.

---

## **5. The Integrity Guard: SBOM Consistency Check**
The final step is a "Sanity Check" to ensure the data provided by the scanner hasn't "drifted" from the reality of the image.

### **The Check: `_verify_sbom_against_df`**
* **Logic:** Every component version used in the final triage report is cross-referenced against the actual package list inside the SBOM.
* **Verification points:**
    1.  Does the package name exist in the SBOM?
    2.  Does the version string (after stripping the RPM epoch) match exactly?
* **Outcome:** If a mismatch is found, the tool issues a warning. This prevents the security team from signing off on a triage report based on stale or incorrect scanner data.

---

## **6. Summary of Verdicts**

| Verdict | Logic Applied |
| :--- | :--- |
| **✅ FALSE POSITIVE** | Vendor states the code is not present/executable, OR the version installed is $\ge$ the fix version for that specific RHEL minor stream. |
| **❌ POSITIVE** | The version installed is older than the fix version, OR the vendor has explicitly marked the product as "Known Affected." |
| **⚠️ MISMATCH** | The triage results do not align with the SBOM package list. Manual intervention is required to verify image contents. |

---

## **7. Conclusion**
By combining **lineage tracking** (SBOM), **minor stream isolation** (RPM math), and **vendor authority** (VEX), this script moves security operations from "Best Effort" guesses to **Provable Integrity**. Every decision made by the script is backed by a specific relationship or version comparison that is 100% auditable.