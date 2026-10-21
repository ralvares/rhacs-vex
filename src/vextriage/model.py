"""What is scanned (Image, Package), what a scanner reports (Finding), what we say (Verdict)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .rpm import EVR, Dist, dist, parse_evr

RED_HAT_REGISTRIES = ('registry.redhat.io', 'registry.access.redhat.com', 'registry.stage.redhat.io',
                      'quay.io/openshift-release-dev')
PAYLOAD_REPOS = ('quay.io/openshift-release-dev/',)

# SBOM/scanner package kinds → VEX purl types
VEX_KIND = {'go': 'golang', 'java': 'maven', 'python': 'pypi', 'rust': 'cargo', 'npm': 'npm',
            'gem': 'gem', 'rpm': 'rpm', 'dotnet': 'nuget'}


@dataclass(eq=False)
class Package:
    kind: str                       # rpm | go | java | npm | python | gem | rust | dotnet | binary | other
    name: str                       # rpm name, Go module path, Maven group:artifact, npm/PyPI name
    version: str                    # rpm: version-release (epoch apart); others as read
    purl: str = ''
    id: str = ''                    # the SBOM's id for it
    epoch: Optional[int] = None     # rpm
    arch: str = ''
    source: str = ''                # rpm: source package name
    module: Optional[str] = None    # rpm: 'nodejs:20' / '' (not modular) / None (unknown)
    vendor: str = ''                # rpm vendor as recorded ('' unknown)
    locations: tuple = ()
    files: frozenset = frozenset()  # rpm: the files it owns
    owner: Optional['Package'] = None   # the rpm whose files carry this package
    main: str = ''                  # go: the binary's main module

    @property
    def evr(self) -> EVR:
        return parse_evr(self.version, self.epoch)

    @property
    def dist(self) -> Dist:
        return dist(self.version)

    @property
    def red_hat_rpm(self) -> Optional[bool]:
        """Built by Red Hat? None when the vendor was not recorded."""
        if self.kind != 'rpm':
            return False
        if not self.vendor:
            return None
        return self.vendor.strip().lower().startswith('red hat')

    def key(self) -> tuple:
        return (self.kind, self.name, self.version, self.locations[:1])


@dataclass
class Image:
    ref: str = ''                   # what was scanned (user input)
    registry: str = ''
    repo: str = ''                  # registry path, namespace/name, lowercase
    labels: dict = field(default_factory=dict)
    digests: set = field(default_factory=set)       # sha256 hex: manifest, repo digests, the ref's
    os_id: str = ''                 # os-release ID (rhel, centos, debian …)
    rhel_major: Optional[int] = None
    rhel_minor: Optional[int] = None
    arch: str = ''
    packages: list = field(default_factory=list)

    @property
    def name_label(self) -> str:
        return (self.labels.get('name') or '').strip().lower()

    @property
    def red_hat(self) -> bool:
        """Red Hat's image: its registry is Red Hat's. An image built FROM ubi keeps
        the base's vendor label, so the label decides only without a registry."""
        if self.registry:
            full = f'{self.registry}/{self.repo}'
            return any(full.startswith(r) or self.registry == r for r in RED_HAT_REGISTRIES)
        return (self.labels.get('vendor') or '').strip().lower().startswith('red hat')

    @property
    def payload(self) -> bool:
        """An OpenShift release payload image (one shared repository; the label names it)."""
        return any(f'{self.registry}/{self.repo}/'.startswith(r) for r in PAYLOAD_REPOS)

    @property
    def built(self) -> Optional[int]:
        """This build's time: the release label's stamp, else the creation labels."""
        from .csaf import build_stamp
        s = build_stamp(self.labels.get('release', ''))
        if s:
            return s
        for k in ('org.opencontainers.image.created', 'build-date'):
            v = self.labels.get(k, '')
            if v:
                import calendar, re
                m = re.match(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})', v)
                if m:
                    return calendar.timegm(tuple(map(int, m.groups())) + (0,))
        return None

    def rpms(self) -> list:
        return [p for p in self.packages if p.kind == 'rpm']


@dataclass(eq=False)
class Finding:
    cve: str
    package: Package
    scanner: str = ''               # grype | trivy | vex (the scan: the SBOM against Red Hat VEX alone)
    vuln_id: str = ''               # the scanner's id (GHSA-…, RHSA-…) when not the CVE
    fixed_in: str = ''              # the scanner's fix version
    severity: str = ''              # the scanner's severity


@dataclass
class Verdict:
    status: str                     # affected | not_affected | fixed | under_investigation
    reason: str                     # one line: why
    stated: bool = False            # Red Hat said it about our product and our package/image/build
    justification: str = ''         # OpenVEX justification (not_affected, stated only)
    fix: str = ''                   # the fix to take (affected) or the fix carried (fixed)
    plan: str = ''                  # Red Hat's plan: Fix deferred, Will not fix, Affected, Out of support scope
    severity: str = ''
    product: str = ''               # the Red Hat product whose statement decided
    evidence: tuple = ()            # product ids of the deciding statements
    rule: str = ''                  # which rule decided (for tests and audits)

    @property
    def positive(self) -> bool:
        return self.status in ('affected', 'under_investigation')
