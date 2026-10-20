"""rhacs_vex — triage scanner findings against Red Hat CSAF-VEX; publish OpenVEX.

    core/          the engine: CSAF statements (csaf), the verdict (judge), the image (workload)
    engine.py      one finding → one verdict (audit_row_detailed)
    audit.py       runs the engine over findings (the batch driver)
    candidates.py  (component, CVE) pairs from an SBOM, the VEX index, OSV, scanners
    vexgen.py      syft SBOM → candidates → engine → OpenVEX statements
    adapters/      finding sources: rhacs, grype, trivy
    cli.py         the `vextriage` command
"""

__version__ = "2.1.0"
