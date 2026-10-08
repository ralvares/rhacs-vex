"""rhacs_vex — triage scanner findings against Red Hat CSAF-VEX; publish OpenVEX.

    core/        the engine: VEX document model, workload scope, decision ladder
    engine.py    its public API (audit_row_detailed, WorkloadContext, …)
    audit.py     runs the engine over findings (the one driver)
    vexgen.py    syft SBOM + Red Hat VEX (+ OSV) → OpenVEX statements
    adapters/    finding sources: rhacs, grype, trivy
    cli.py       the `vextriage` command
"""

__version__ = "2.0.0"
