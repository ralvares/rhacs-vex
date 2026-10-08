"""One Red Hat CSAF-VEX document, parsed once into what triage needs.

Red Hat publishes one CSAF file per CVE.  Every question the engine asks of it —
"what package does this product_id name", "which parent product is it under",
"what does Red Hat say about it", "how severe for that product", "what is the
remediation plan" — is answered from the tables built here, so no rung ever
re-walks the raw JSON (VEX-MODEL §3, §4, §5).

Identity of record is the purl (99.88% of status refs carry one); the PID string
grammar is only the fallback for upstream pseudo-components.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Tuple
from urllib.parse import unquote

STATUSES = ('known_affected', 'known_not_affected', 'fixed', 'under_investigation')
OPEN = ('known_affected', 'under_investigation')
CLEAR = ('known_not_affected', 'fixed')

# CSAF flag labels that all mean "not affected" (§5b).
NOT_AFFECTED_FLAGS = frozenset({
    'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'component_not_present',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist',
})

_ARCH_ALT = (r'x86_64|aarch64|ppc64le|ppc64|ppc|s390x|s390|i686|i586|i486|i386'
             r'|ia64|armv7hl|armv5tel|noarch|source|src')
_ARCH_SUFFIX_RE = re.compile(r'\.(?:' + _ARCH_ALT + r')$')
_SHA_RE = re.compile(r'@sha256:([a-f0-9]+)', re.IGNORECASE)


# ── PID primitives ───────────────────────────────────────────────────────────

def digest_of(ref: str) -> Optional[str]:
    """sha256 hex of an image ref or PID, ignoring the per-arch '_amd64' tail."""
    m = _SHA_RE.search(ref)
    return m.group(1) if m else None


def parent_of(pid: str) -> str:
    return pid.split(':')[0]


def component_of(pid: str) -> str:
    """The component half of a composite PID (everything after the first ':')."""
    return pid.split(':', 1)[1] if ':' in pid else pid


def rpm_purl_identity(purl: str) -> Tuple[Optional[str], Optional[str]]:
    """(name, version-release) from an rpm purl.

    Percent-decoding is load-bearing (`module%2Bel8` → '+').  Only the vendor
    namespace is stripped: `pkg:rpm/redhat/openshift4/ose-cli` keeps its '/',
    which routes it to the image path (§3a rule 5).
    """
    if not purl.startswith('pkg:rpm/'):
        return None, None
    body = unquote(purl.partition('?')[0][len('pkg:rpm/'):])
    path, _, version = body.partition('@')
    name = path.partition('/')[2] or path
    return (name or None), (version or None)


def parse_pid(pid: str) -> Tuple[Optional[str], Optional[str]]:
    """(name, version-release) from the PID string — fallback when no purl.

    Strip '::module:stream', take the component, split on the epoch colon,
    drop a trailing arch.  Bare leaves return (name, None).
    """
    pid = pid.split('::')[0]
    colon = pid.find(':')
    if colon < 0:
        return None, None
    comp = pid[colon + 1:]
    m = re.search(r'-(\d+):', comp)
    if m:
        rest = comp[m.end():]
        a = _ARCH_SUFFIX_RE.search(rest)
        return comp[:m.start()], (rest[:a.start()] if a else rest)
    return _ARCH_SUFFIX_RE.sub('', comp), None


def is_src_pid(pid: str) -> bool:
    return pid.split('::')[0].endswith('.src')


# ── the document ─────────────────────────────────────────────────────────────

@dataclass
class Vuln:
    """One `vulnerabilities[]` entry: product_status lists in JSON order."""
    status: Dict[str, List[str]]
    all_flags: List[Tuple[str, List[str]]]      # (label, product_ids), every label
    remediations: List[dict]

    @property
    def flags(self) -> List[Tuple[str, List[str]]]:
        """Only the flags meaning "not affected" (§5b)."""
        return [f for f in self.all_flags if f[0] in NOT_AFFECTED_FLAGS]

    def pids(self, *statuses) -> Iterator[Tuple[str, str]]:
        for st in statuses:
            for pid in self.status.get(st, ()):
                yield st, pid

    def flag_pids(self) -> Iterator[Tuple[str, str]]:
        for label, pids in self.flags:
            for pid in pids:
                yield label, pid

    def flag_label(self) -> Dict[str, str]:
        """pid → label over ALL flags of this entry (later flags win)."""
        out = {}
        for label, pids in self.all_flags:
            for pid in pids:
                out[pid] = label
        return out


class VexDocument:
    """Lookup tables over one CSAF-VEX file.  Build with VexDocument.of(data)."""

    def __init__(self, data: dict):
        # The raw document is NOT kept: a parsed CSAF file runs to hundreds of
        # MB for the largest CVEs, the tables below are a fraction of that.
        tree = data.get('product_tree', {}) or {}
        self.name: Dict[str, str] = {}
        self.purl: Dict[str, str] = {}
        self.cpe: Dict[str, str] = {}
        self._walk(tree.get('branches', []))

        # package identity straight off rpm purls, keyed by bare and composite PID
        self.ident: Dict[str, tuple] = {}
        for pid, purl in self.purl.items():
            n, v = rpm_purl_identity(purl)
            if n:
                self.ident[pid] = (n, v)

        self.parent_label: Dict[str, str] = {}   # composite pid → parent product name
        self.comp_parent: Dict[str, str] = {}    # component pid → parent pid
        for rel in tree.get('relationships', []):
            fpid = rel.get('full_product_name', {}).get('product_id', '')
            parent = rel.get('relates_to_product_reference', '')
            comp = rel.get('product_reference', '')
            if fpid and parent:
                self.parent_label[fpid] = self.name.get(parent, parent)
            if comp and parent:
                self.comp_parent[comp] = parent
            if fpid and comp and comp in self.ident:
                self.ident[fpid] = self.ident[comp]

        self.rhel_base = {p for p, n in self.name.items()
                          if n.startswith('Red Hat Enterprise Linux')}
        self.ns_products = self._oci_namespace_map()

        self.vulns: List[Vuln] = []
        self.severity: Dict[str, str] = {}
        self.remediation: Dict[str, List[tuple]] = {}
        for v in data.get('vulnerabilities', []):
            flags_all = [(f.get('label', ''), list(f.get('product_ids', [])))
                         for f in v.get('flags', [])]
            self.vulns.append(Vuln(
                status={s: list(v.get('product_status', {}).get(s, [])) for s in STATUSES},
                all_flags=flags_all, remediations=v.get('remediations', [])))
            for t in v.get('threats', []):
                if t.get('category') == 'impact' and t.get('details'):
                    for pid in t.get('product_ids', []):
                        self.severity[pid] = t['details'].title()
            for r in v.get('remediations', []):
                cat, det = r.get('category', ''), (r.get('details') or '').strip()
                for pid in r.get('product_ids', []):
                    self.remediation.setdefault(pid, []).append((cat, det))

        self.catchall_not_affected = self._catchall(tree)
        # document-level severity fallbacks (§8d tiers 5-7)
        agg = ((data.get('document') or {}).get('aggregate_severity') or {}).get('text', '')
        self.aggregate_severity = agg.title() if agg.strip().lower() not in ('', 'none') else ''
        self.any_impact, self.any_cvss = '', ''
        for v in data.get('vulnerabilities', []):
            t = next((t for t in v.get('threats', [])
                      if t.get('category') == 'impact' and t.get('details')), None)
            if t and not self.any_impact:
                self.any_impact = t['details'].title()
            base = next(((sc.get('cvss_v3') or sc.get('cvss_v2') or {}).get('baseSeverity', '').upper()
                         for sc in v.get('scores', [])
                         if (sc.get('cvss_v3') or sc.get('cvss_v2') or {}).get('baseSeverity')), '')
            if base and not self.any_cvss:
                self.any_cvss = base
        self._src_vr = None
        self.scope_cache: dict = {}

    @classmethod
    def of(cls, data) -> "VexDocument":
        """A VexDocument for *data* (already one, or a raw dict — parsed once and
        cached on the dict the caller holds)."""
        if isinstance(data, VexDocument):
            return data
        doc = data.get('__vexdoc__')
        if doc is None:
            doc = cls(data)
            data['__vexdoc__'] = doc
        return doc

    # ── tree ────────────────────────────────────────────────────────────────
    def _walk(self, branches):
        for b in branches:
            p = b.get('product', {})
            pid = p.get('product_id')
            if pid:
                self.name[pid] = p.get('name', '')
                helper = p.get('product_identification_helper') or {}
                if helper.get('purl'):
                    self.purl[pid] = helper['purl']
                if helper.get('cpe'):
                    self.cpe[pid] = helper['cpe']
            self._walk(b.get('branches', []))

    def _oci_namespace_map(self) -> Dict[str, set]:
        """registry namespace → {parent pids, parent CPE product tokens} (§8a)."""
        out: Dict[str, set] = {}
        for comp, purl in self.purl.items():
            if not purl.startswith('pkg:oci/'):
                continue
            m = re.search(r'repository_url=[^/]+/([^/&]+)', purl)
            parent = self.comp_parent.get(comp)
            if not (m and parent):
                continue
            entry = out.setdefault(m.group(1).lower(), set())
            entry.add(parent)
            parts = self.cpe.get(parent, '').replace('cpe:/', '').split(':')
            if len(parts) > 2:
                entry.add(parts[2])
        return out

    def _catchall(self, tree: dict) -> bool:
        """Vendor catch-all (`red_hat_products`, or a bare `cpe:/a:redhat` node)
        marked not affected (§1g, rung 1)."""
        nodes = {'red_hat_products'}
        for b in tree.get('branches', []):
            prod = b.get('product', {})
            cpe = str((prod.get('product_identification_helper') or {}).get('cpe', ''))
            toks = [p for p in cpe.split(':') if p not in ('', 'cpe', '/a', '/o', '/h')]
            if len(toks) == 1 and toks[0].lower() in ('redhat', 'red_hat') and prod.get('product_id'):
                nodes.add(prod['product_id'])
        for v in self.vulns:
            clear = set(v.status['known_not_affected']) | {p for _l, p in v.flag_pids()}
            if nodes & clear:
                return True
        return False

    # ── per-PID reads ───────────────────────────────────────────────────────
    def package(self, pid: str) -> Tuple[Optional[str], Optional[str]]:
        """(name, version-release) of a status PID — purl first, PID grammar after."""
        got = self.ident.get(pid)
        return got if got is not None else parse_pid(pid)

    def label(self, pid: str) -> str:
        """Human-readable product name for a PID."""
        if pid in self.parent_label:
            return self.parent_label[pid]
        parent = parent_of(pid)
        return self.name.get(parent, parent)

    def is_generic(self, pkg: str) -> bool:
        return self.purl.get(pkg, '').startswith('pkg:generic/')

    def pid_severity(self, pid: str) -> Optional[str]:
        """Impact threat of a PID: direct key, else a composite ending in ':pid'."""
        if pid in self.severity:
            return self.severity[pid]
        for k, sev in self.severity.items():
            if k.endswith(':' + pid):
                return sev
        return None

    def build_digest(self, pid: str) -> Optional[str]:
        """sha256 hex of the build a PID names: in the PID, else in its oci purl.

        Konflux-era statements can name an image by path alone while the purl
        pins the build (`rhoai/odh-dashboard-rhel9` → `pkg:oci/…@sha256%3A…`);
        purls write the digest percent-encoded.
        """
        d = digest_of(pid)
        if d:
            return d.lower()
        purl = self.purl.get(component_of(pid)) or self.purl.get(pid) or ''
        m = re.search(r'@sha256(?::|%3A)([a-f0-9]{64})', purl, re.IGNORECASE)
        return m.group(1).lower() if m else None

    def purl_for(self, pid: str) -> Optional[str]:
        leaf = component_of(pid)
        purl = self.purl.get(pid) or self.purl.get(leaf)
        if purl:
            return purl
        for k, v in self.purl.items():
            if leaf.endswith(k) or k.endswith(leaf):
                return v
        return None

    # ── document-wide walks ─────────────────────────────────────────────────
    def pids(self, *statuses) -> Iterator[Tuple[str, str]]:
        """(status, pid) vuln-major, statuses in the order given."""
        for v in self.vulns:
            yield from v.pids(*statuses)

    def flag_pids(self) -> Iterator[Tuple[str, str]]:
        for v in self.vulns:
            yield from v.flag_pids()

    def oci_matches(self, candidates: list) -> set:
        """Component PIDs whose OCI purl names the workload image (§4a, rung 3a).

        Exact repository_url wins; else pkg:oci/<name> equality bridges the
        Brew-label ↔ registry namespace split.  Both purl eras are handled by
        composing repository_url + the purl name's last segment.
        """
        if not candidates:
            return set()
        repos = {c[0] for c in candidates}
        names = {c[1] for c in candidates}
        by_repo, by_name = set(), set()
        for pid, purl in self.purl.items():
            if not purl.startswith('pkg:oci/'):
                continue
            m = re.match(r'pkg:oci/([^?@]+)', purl)
            pname = m.group(1) if m else ''
            last = pname.split('/')[-1]
            r = re.search(r'repository_url=([^&]+)', purl)
            if r:
                repo = r.group(1)
                if last and not repo.endswith('/' + last):
                    repo = f"{repo}/{last}"
                if repo in repos:
                    by_repo.add(pid)
                    continue
            if pname in names or (last and last in names):
                by_name.add(pid)
        return by_repo or by_name

    def src_versions(self) -> Dict[str, set]:
        """source name → {version-release | None} over every `.src` status PID."""
        if self._src_vr is None:
            out: Dict[str, set] = {}
            for _st, pid in self.pids(*STATUSES):
                if is_src_pid(pid):
                    name, vr = self.package(pid)
                    if name:
                        out.setdefault(name, set()).add(vr)
            self._src_vr = out
        return self._src_vr

    def product_summary(self):
        """(affected, fixed, not_affected, investigating) product labels, sorted."""
        buckets = {s: set() for s in STATUSES}
        for st, pid in self.pids(*STATUSES):
            buckets[st].add(self.label(pid))
        for _l, pid in self.flag_pids():
            buckets['known_not_affected'].add(self.label(pid))
        return (sorted(buckets['known_affected']), sorted(buckets['fixed']),
                sorted(buckets['known_not_affected']),
                sorted(buckets['under_investigation']))

    def fixed_ocp_streams(self) -> set:
        """OCP minors with a `fixed` RHOSE stream PID ('4.16')."""
        out = set()
        for _st, pid in self.pids('fixed'):
            m = re.search(r'RHOSE[.-](\d+\.\d+)', pid)
            if m:
                out.add(m.group(1))
        return out
