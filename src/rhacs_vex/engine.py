"""vex_engine.py — RHACS ↔ Red Hat CSAF-VEX matching engine.

A single evaluation pipeline that, for one (scanner-finding row, workload
context), reconciles the scanner identity against the Red Hat VEX product model
and returns one coherent answer:

    audit_row_detailed(row, ctx) -> pd.Series([verdict, fix, justification,
                                               severity, state])

Built clean-room from VEX-MODEL.md.  The defining property — and the reason it
replaces the previous engine — is that VERDICT, SEVERITY, STATE and FIX are all
read from the *same decisive match* instead of four independent searches that
could disagree.  The pipeline is:

    1. resolve identity once      (workload identity + component name set)      §4,§8a
    2. collect candidate matches  (one walk over product_status + flags)        §5,§8
    3. decide the verdict         (ordered ladder, first decisive rung wins)    §8b
    4. read severity/state/fix    (from the decisive PID's threats/remediations)§8d

Decision ladder (VEX-MODEL §8b), first decisive rung wins:

    1  vendor catch-all      red_hat_products / bare cpe:/a:redhat not-affected → FALSE POSITIVE
    2  our-digest override   a PID carries our image's exact @sha256 digest     → per-build verdict
    ── split RPM vs non-RPM (a '/' in the component or no .elN marker ⇒ non-RPM) ──
    RPM (rungs 5,5s,8,9):
    5  component in scope    name+dist-tag+minor+module+CPE scoped, status
                             priority KNA>fixed>KA>UI; fixed → §6 version compare
    8  related products      same package in out-of-scope RHEL-N / neutral PIDs
    9  not listed            no VEX statement names the component (§5g: the
                             errata assumption covers only listed products)     → FALSE POSITIVE
    non-RPM (rungs 3,4,6,7,8,9):
    3  image identity        OCI-purl / image-path / generic component match
    4  same-image other build RHEL-variant-quality + SHA-specificity ranking
    7  errata policy         OCP version vs RHOSE-4.x fixed streams (§5g)
    6  product-family clear   all in-scope PIDs clear, none affected            → FALSE POSITIVE
    9  not listed                                                               → FALSE POSITIVE

Scoping is structural (CPE + dist-tag decoder + product-tree names), never a
hardcoded product/host list.  Per-CVE lookup maps are memoized inside the
(lru-cached) VEX dict so the product tree is walked once per CVE.

Primitives whose exact expression is a validated rule mined in VEX-MODEL (RPM
version compare, epoch alignment, dist-tag decode, PID grammar, CPE prefix
match, OCI-purl match, catch-all detection) are reused verbatim; the four-search
orchestration they used to feed is what this module replaces.
"""

import functools
import os
import re
import json
from dataclasses import dataclass, field
from typing import Optional, List
from urllib.parse import unquote


# ── Config ────────────────────────────────────────────────────────────────────
BASE_DIR = "data"
VEX_DIR  = os.path.join(BASE_DIR, "vex")


# ══════════════════════════════════════════════════════════════════════════════
# §2/§3/§6  Version, dist-tag and PID-grammar primitives (validated expressions)
# ══════════════════════════════════════════════════════════════════════════════

def compare_versions(a: str, b: str) -> int:
    """RPM version comparison with proper epoch handling (VEX-MODEL §3e/§6e).

    Epoch format: "EPOCH:VERSION-RELEASE".  Missing epoch defaults to 0; a
    higher epoch always wins regardless of the version-release string.
    """
    def _parse_epoch(v):
        if ':' in v:
            parts = v.split(':', 1)
            try:
                return int(parts[0]), parts[1]
            except ValueError:
                return 0, v
        return 0, v

    epoch_a, ver_a = _parse_epoch(a)
    epoch_b, ver_b = _parse_epoch(b)
    if epoch_a != epoch_b:
        return 1 if epoch_a > epoch_b else -1
    return _evr_compare(ver_a, ver_b)


def _rpmvercmp(a: str, b: str) -> int:
    """rpmvercmp — segment-wise comparison of ONE version or release string.

    Ported from rpm's lib/rpmvercmp.c: walk both strings, skipping any character
    that is not alphanumeric, '~' or '^'.  Numeric runs compare numerically
    (leading zeros stripped, longer run wins); alphabetic runs compare
    lexically; a numeric run outranks an alphabetic one.  '~' sorts BEFORE
    everything (pre-releases: 1.0~rc1 < 1.0) and '^' after.  When one side runs
    out first the other is newer.
    """
    if a == b:
        return 0
    i, j, la, lb = 0, 0, len(a), len(b)
    while i < la or j < lb:
        while i < la and not (a[i].isalnum() or a[i] in '~^'):
            i += 1
        while j < lb and not (b[j].isalnum() or b[j] in '~^'):
            j += 1

        # '~' sorts before anything, including the end of the string
        if (i < la and a[i] == '~') or (j < lb and b[j] == '~'):
            if i >= la or a[i] != '~':
                return 1
            if j >= lb or b[j] != '~':
                return -1
            i += 1
            j += 1
            continue
        # '^' sorts after everything except the end of the string
        if (i < la and a[i] == '^') or (j < lb and b[j] == '^'):
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if a[i] != '^':
                return 1
            if b[j] != '^':
                return -1
            i += 1
            j += 1
            continue

        if i >= la or j >= lb:
            break

        start_a, start_b = i, j
        isnum = a[i].isdigit()
        if isnum:
            while i < la and a[i].isdigit():
                i += 1
            while j < lb and b[j].isdigit():
                j += 1
        else:
            while i < la and a[i].isalpha():
                i += 1
            while j < lb and b[j].isalpha():
                j += 1
        seg_a, seg_b = a[start_a:i], b[start_b:j]
        if not seg_b:
            # a has a numeric segment where b has an alphabetic one (or none)
            return 1 if isnum else -1
        if isnum:
            seg_a, seg_b = seg_a.lstrip('0') or '0', seg_b.lstrip('0') or '0'
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1

    if i >= la and j >= lb:
        return 0
    # whichever side still has characters left is the newer one
    return 1 if i < la else -1


def _evr_compare(a: str, b: str) -> int:
    """Compare VERSION[-RELEASE] the way RPM does: version first, release only
    as a tie-breaker.

    Replaces version_utils.rpm.compare_versions, which decides some pairs on the
    RELEASE even when the VERSIONS already differ:

        compare_versions('1.1.1-9.el8', '1.1.1k-4.el8')  ->  +1

    1.1.1 is older than 1.1.1k, so that answer marks a genuinely vulnerable
    build as "installed >= fix" — a false suppression.  It hits every package
    whose upstream version carries a letter suffix (openssl 1.1.1k / 1.0.2k /
    3.0.7a being the obvious ones).
    """
    ver_a, _, rel_a = a.partition('-')
    ver_b, _, rel_b = b.partition('-')
    c = _rpmvercmp(ver_a, ver_b)
    if c:
        return c
    if not rel_a or not rel_b:
        # one side quotes a bare version — versions tie, nothing more to compare
        return 0
    return _rpmvercmp(rel_a, rel_b)


def _normalize_epoch(installed: str, fix: str) -> tuple:
    """Align epoch prefixes before compare_versions (VEX-MODEL §3e).

    VEX fixed versions often omit the epoch the RPM carries; both describe the
    same source package, so the present epoch is propagated to the side lacking
    it.
    """
    inst_m = re.match(r'^(\d+):', installed)
    fix_m  = re.match(r'^(\d+):', fix)
    if inst_m and not fix_m:
        fix = f"{inst_m.group(1)}:{fix}"
    elif fix_m and not inst_m:
        installed = f"{fix_m.group(1)}:{installed}"
    return installed, fix


def _detect_rhel_ver(version_str: str):
    """RHEL major from an RPM release string ('...el8', '...+el8.4...') (§2)."""
    m = re.search(r'[.+]el(\d+)', version_str)
    return m.group(1) if m else None


def _detect_rhel_minor(version_str: str):
    """RHEL minor stream from a release string (VEX-MODEL §2, §6a).

    '3.9.18-3.el9_4.10' → '4'  ·  '2.4.37-64.module+el8.10.0+' → '10'  ·
    '3.6.8-59.el8' → None
    """
    m = re.search(r'\.el\d+_(\d+)', version_str)
    if m:
        return m.group(1)
    m = re.search(r'[.+]el(\d+)\.(\d+)\.', version_str)
    if m:
        return m.group(2)
    return None


def _rpm_stream_family(version_str: str):
    """Build lineage of an rpm version-release string.

    OCP-built rpms carry a `rhaosX.Y` disttag ('5.4.0-14.rhaos4.21.el9');
    RHEL-built rpms don't ('4.2.0-6.el9_0.6').  The two lineages version
    independently (RHEL podman 4.x vs OCP podman 5.x), so their NEVRAs are
    never comparable.

    The dist-tag SUFFIX splits lineages the same way (§2): `el8pc` is Satellite
    Capsule, `el9cp` Ceph, `el9ap` Ansible AP, `el8ost` OpenStack, `el9fdp` Fast
    Datapath, `el7a` RHEL Alt, `hum` Red Hat Hardened Images.  Each ships its own
    build of a shared package — libsolv is 0.7.20 in RHEL 8 base and 0.7.22 in
    Satellite — so comparing across them makes a current base package look
    permanently behind.  A base build ('el8', 'el8_6', 'module+el8.10.0') has no
    suffix.  Returns ('rhaos', 'X.Y'), ('hum', None) or ('el', suffix|None).
    """
    v = str(version_str or '')
    m = re.search(r'(?:^|[.+])rhaos(\d+\.\d+)(?:[.+]|$)', v)
    if m:
        return ('rhaos', m.group(1))
    if re.search(r'(?:^|[.+])hum\d*(?:[.+]|$)', v):
        return ('hum', None)
    m = re.search(r'[.+]el\d+(?:_\d+)?([a-z]+)', v)
    return ('el', m.group(1) if m else None)


def _stream_comparable(installed_v, candidate_v) -> bool:
    """May a VEX NEVRA be version-compared against the installed rpm?

    Same lineage only: an el-family fix must not clear (or fail) a rhaos
    build and vice versa; two rhaos builds must share the OCP minor.
    """
    fam_i, ver_i = _rpm_stream_family(installed_v)
    fam_c, ver_c = _rpm_stream_family(candidate_v)
    if fam_i != fam_c:
        return False
    if fam_i == 'rhaos':
        return ver_i == ver_c
    # base RHEL vs a layered product's own build of the same package
    return ver_i == ver_c


def _extract_sha256(ref: str):
    """sha256 hex from an image reference or VEX PID (VEX-MODEL §3c/§4c).

    Handles 'registry/image@sha256:HEX' and 'STREAM:registry/image@sha256:HEX',
    ignoring any trailing per-arch suffix ('_amd64', …).
    """
    m = re.search(r'@sha256:([a-f0-9]+)', ref, re.IGNORECASE)
    return m.group(1) if m else None


def _own_shas(ctx) -> set:
    """Every sha256 hex identifying THIS build (VEX-MODEL §3c/§4c 'our digest').

    Pull-ref digest plus ctx.extra_digests (platform manifest digest, repo
    digests).  VEX PIDs list per-arch manifest digests, so matching only the
    multi-arch list digest from the pull ref misses exact-build assessments.
    """
    shas = set()
    m = re.search(r'@sha256:([a-f0-9]+)', ctx.image_ref or '', re.IGNORECASE)
    if m:
        shas.add(m.group(1).lower())
    for d in getattr(ctx, 'extra_digests', None) or []:
        m = re.search(r'([a-f0-9]{64})', str(d).lower())
        if m:
            shas.add(m.group(1))
    return shas


def _pid_module_stream(pid: str):
    """The '::module:stream' token of a PID (VEX-MODEL §3d), or None."""
    if '::' in pid:
        return pid.split('::', 1)[1]
    return None


def _version_is_module_stream(ver: str) -> bool:
    """True when an RPM release marks a module build ('.module+') (§6d)."""
    return '.module+' in ver or '+module+' in ver


def _module_stream_compatible(pid: str, found_v: str) -> bool:
    """Does a '::module:stream' PID apply to the installed version? (§6d, §9.1a)

    An installed release carrying '.module+' is a module build — compatible;
    the version compare decides from there.  Without the marker (scanners can
    normalize the release string — the §9.1a fragility), fall back to the
    stream structure itself: a numeric stream ('perl:5.32', 'nodejs:18') must
    version-prefix the installed version and the RHEL major must agree.  A
    non-numeric stream ('container-tools:rhel8') stays incompatible — nothing
    in the installed version can verify it.  Non-module PIDs always apply.
    """
    stream = _pid_module_stream(pid)
    if stream is None:
        return True
    if _version_is_module_stream(found_v):
        return True
    tok = stream.rsplit(':', 1)[-1]
    if not re.fullmatch(r'\d+(\.\d+)*', tok):
        return False
    inst = found_v.split(':', 1)[-1] if ':' in found_v else found_v
    if not (inst == tok or inst.startswith(tok + '.') or inst.startswith(tok + '-')):
        return False
    pid_el = re.search(r'\.module\+el(\d+)', pid) or re.search(r'\.el(\d+)[._]', pid.split('::')[0])
    inst_el = re.search(r'\.el(\d+)', inst)
    if pid_el and inst_el and pid_el.group(1) != inst_el.group(1):
        return False
    return True


# Every arch token the corpus actually uses as an `arch=` purl qualifier, longest
# first so the alternation cannot match a prefix (ppc64le before ppc64 before
# ppc, s390x before s390).  Measured over data/vex: x86_64, aarch64, ppc64le,
# s390x, src, noarch, i686, ppc64, ppc, s390, i386, ia64, i586, source.
_ARCH_ALT = (r'x86_64|aarch64|ppc64le|ppc64|ppc|s390x|s390|i686|i586|i486|i386'
             r'|ia64|armv7hl|armv5tel|noarch|source|src')
_ARCH_SUFFIX_RE = re.compile(r'\.(?:' + _ARCH_ALT + r')$')


def _purl_ident(purl: str):
    """(package_name, version_release) from an rpm purl — the identity of record.

    Red Hat's own csaf-lib models `product_id` as an opaque string and parses
    only `product_identification_helper.purl` (PackageURL.from_string), so the
    purl — not the PID — is the sanctioned identity.  It carries the version for
    every versioned node; `arch`/`epoch`/`rpmmod` are qualifiers, so nothing has
    to be sliced off the version.

    Percent-decoding is load-bearing: module builds are written
    `2.4.37-51.module%2Bel8.7.0%2B18026` and the `.module+` test in
    _version_is_module_stream (plus the RPM version compare) needs the literal
    '+' back.  Returns (None, None) for non-rpm purls; a version-less node
    (`pkg:rpm/redhat/tar?arch=src`) returns (name, None) like a bare leaf PID.

    Only the vendor namespace is dropped, never a deeper path: 713 nodes carry a
    product path (`pkg:rpm/redhat/openshift4/ose-cli`) and the surviving '/' is
    what routes the component to the non-RPM ladder (VEX-MODEL §3a rule 5, §8b).
    Every rpm purl in the corpus uses the `redhat` namespace (3,982,862 of
    3,982,862), so the prefix is stripped positionally rather than by name.
    """
    if not purl.startswith('pkg:rpm/'):
        return None, None
    body = unquote(purl.partition('?')[0][len('pkg:rpm/'):])
    path, _, version = body.partition('@')
    name = path.partition('/')[2] or path
    return (name or None), (version or None)


def _parse_pkg_from_product_id(pid: str):
    """(package_name, version_release) from a VEX product_id (VEX-MODEL §3a).

    Fallback for the ~0.1% of statement refs whose component node ships no purl
    (upstream-project pseudo-components such as `jackson-databind`).  Red Hat
    publishes no product_id grammar, so this is reverse-engineered: strip the
    '::module:stream' suffix, take the component after the first ':', split on
    the epoch colon ('-<digits>:') into name / ver-rel, and drop a trailing
    arch.  Bare leaf PIDs return (name, None).  Prefer _purl_ident.
    """
    pid = pid.split('::')[0]
    colon = pid.find(':')
    if colon < 0:
        return None, None
    component_part = pid[colon + 1:]
    epoch_match = re.search(r'-(\d+):', component_part)
    if epoch_match:
        name = component_part[:epoch_match.start()]
        rest = component_part[epoch_match.end():]
        arch_match = _ARCH_SUFFIX_RE.search(rest)
        if arch_match:
            rest = rest[:arch_match.start()]
        return name, rest
    component_part = _ARCH_SUFFIX_RE.sub('', component_part)
    return component_part, None


def _pkg_from_pid(pid: str, pid_ident: dict):
    """(package_name, version_release) for a status PID — purl first.

    *pid_ident* is the purl-derived map from _build_pid_name, keyed by both the
    composite `<parent>:<component>` PID used in product_status and the bare
    component PID.  Falls back to the string parse when the node has no purl.
    """
    ident = pid_ident.get(pid) if pid_ident else None
    if ident is not None:
        return ident
    return _parse_pkg_from_product_id(pid)


# ══════════════════════════════════════════════════════════════════════════════
# §7  Workload identity (scanner side) — parsed from image ref + labels
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class WorkloadContext:
    """The workload being triaged, so VEX product-ID matching can be scoped.

    workload_type ∈ {"ubi", "ocp", "operator"}.  `cpe` is the raw image-label
    CPE; `ocp_component` is the OCP manifest component (e.g. "etcd");
    `sbom_src_map`/`sbom_packages` are populated by callers that have SBOM
    access (binary→source RPM aliasing and version verification).
    """
    image_ref     : Optional[str]   = None
    rhel_ver      : str             = "8"
    workload_type : str             = "ubi"
    ocp_ver       : Optional[str]   = None
    image_ns      : Optional[str]   = None
    image_name    : Optional[str]   = None
    display_name  : str             = "UBI8"
    extra_prefixes: List[str]       = field(default_factory=list)
    sbom_src_map  : dict            = field(default_factory=dict)
    sbom_packages : dict            = field(default_factory=dict)
    ocp_component : Optional[str]   = None
    cpe           : Optional[str]   = None
    image_build   : Optional[str]   = None   # version-release of THIS build (labels/tag)
    extra_digests : List[str]       = field(default_factory=list)
    # Additional sha256 identities of THIS build (platform manifest digest,
    # repo digests) from SBOM/scanner metadata.  VEX PIDs carry per-arch
    # manifest digests, while a pull ref usually carries the multi-arch list
    # digest — without these the our-digest override never fires.


_NS_VEX_MAP_PATH = os.path.join(BASE_DIR, "ns_vex_prefixes.json")


def _load_ns_vex_map() -> dict:
    """Catalog-generated namespace→VEX-prefix map (data/ns_vex_prefixes.json)."""
    try:
        with open(_NS_VEX_MAP_PATH) as _fh:
            return json.load(_fh)
    except Exception:
        return {}


_NS_TO_VEX_PREFIXES = _load_ns_vex_map()


def _normalize_vex_image_core(img: str) -> str:
    """OCP component core from a VEX image-style PID component (VEX-MODEL §8 3b).

    'openshift4/ose-etcd-rhel9' → 'etcd'  ·
    'openshift4/ose-cluster-etcd-rhel8-operator' → 'cluster-etcd-operator'
    """
    if '/' in img:
        img = img.split('/', 1)[1]
    if img.startswith('ose-'):
        img = img[4:]
    img = re.sub(r'-rhel\d+', '', img)
    img = re.sub(r'--+', '-', img).strip('-')
    return img


def _extract_rhel_from_vex_image(img: str):
    """RHEL major from a VEX image PID ('-rhel9'), or None."""
    m = re.search(r'-rhel(\d+)', img)
    return m.group(1) if m else None


# RHCOS ships as a bare generic PID (pkg:generic/redhat/rhcos); the OCP release
# manifest names it 'rhel-coreos-<N>'.  Normalise both to a common core (§8 3b).
_OCP_GENERIC_ALIASES = {'rhcos': 'rhel-coreos'}


def _normalize_ocp_component(name: str) -> str:
    """Normalise OCP manifest / VEX generic component names for matching."""
    name = name.lower()
    if name in _OCP_GENERIC_ALIASES:
        return _OCP_GENERIC_ALIASES[name]
    name = re.sub(r'^(rhel-coreos)-\d+$', r'\1', name)
    return name


def parse_image_ref(image_ref: str, os_hint: str = "") -> WorkloadContext:
    """Parse a Red Hat container image reference into a WorkloadContext.

    Namespace/type classification is structural + catalog-map driven; no
    hardcoded product list.  *os_hint* is the scanner's OS string and overrides
    the rhel_ver guessed from the path — the path of an OCP payload image
    (`openshift-release-dev/ocp-v4.0-art-dev`) encodes no RHEL major at all, so
    without it the "8" default silently wins on a RHEL 9/10 image.
    """
    ctx = WorkloadContext(image_ref=image_ref)

    path = re.sub(r'^[^/]+/', '', image_ref)     # remove registry host
    path = re.sub(r'[@:][^/]*$', '', path)       # remove tag/digest
    parts = path.split('/', 1)
    ns   = parts[0].lower() if parts else ""
    name = parts[1].lower() if len(parts) > 1 else ""
    ctx.image_ns   = ns
    ctx.image_name = name

    rv = re.search(r'rhel(\d+)', name) or re.search(r'rhel(\d+)', ns) \
        or re.search(r'^ubi(\d+)$', ns)
    ctx.rhel_ver = rv.group(1) if rv else "8"
    if os_hint:
        om = re.search(r'(?:rhel|coreos|redhat)[^0-9]{0,3}(\d+)', str(os_hint).lower())
        if om:
            ctx.rhel_ver = om.group(1)

    ocp_tag = re.search(r'v(4\.\d+)', image_ref)
    if ocp_tag:
        ctx.ocp_ver = ocp_tag.group(1)

    ubi_ns = re.match(r'^ubi\d+', ns) or name == "" or ns in ("ubi", "rhel")
    ocp_ns = ns in ("openshift4", "openshift", "ocp4", "openshift-release-dev") \
        or "ose-" in name or name.startswith("ocp-")

    if ubi_ns:
        ctx.workload_type = "ubi"
        ctx.display_name  = f"UBI{ctx.rhel_ver}"
    elif ocp_ns:
        ctx.workload_type = "ocp"
        ctx.display_name  = f"OpenShift {ctx.ocp_ver or '4.x'}"
    else:
        ctx.workload_type = "operator"
        registry = re.match(r'^([^/]+)/', image_ref)
        reg_host = registry.group(1) if registry else "registry.redhat.io"
        ctx.extra_prefixes.append(f"{reg_host}/{ns}/")
        ctx.extra_prefixes.append(f"{ns}/")
        for ns_key, prefixes in _NS_TO_VEX_PREFIXES.items():
            if ns_key == ns or ns_key in ns:
                for p in prefixes:
                    if p not in ctx.extra_prefixes:
                        ctx.extra_prefixes.append(p)
        ver_label = f" (RHEL {ctx.rhel_ver})"
        ctx.display_name = f"{ns}/{name}{ver_label}"

    return ctx


def parse_context_from_labels(labels: dict, image_ref: str = "",
                              os_hint: str = "") -> WorkloadContext:
    """Derive a WorkloadContext from container image labels (VEX-MODEL §7c/§7d).

    The registry pull path is authoritative for the RHEL variant (labels can lag
    a rebuild); the CPE label refines RHEL major, product version, and promotes
    a plain-'openshift' CPE product to the OCP workload type.  *os_hint* is the
    scanner's own OS string (RHACS `scan.operatingSystem`, grype `distro`) and
    outranks all of them — it was read from inside the image.
    """
    cpe  = labels.get("cpe", "")
    name = labels.get("name", "")

    ref = f"registry.redhat.io/{name}" if "/" in name else (image_ref or "")
    ctx = parse_image_ref(ref) if ref else WorkloadContext()
    if image_ref:
        ctx.image_ref = image_ref

    # The label namespace above wins for identity (the art-dev pull path names no
    # image), but it is the *secondary* signal per §7d and disagrees with the
    # registry path on 18-46% of images — always in the direction that loses the
    # namespace map: label `managed-open-data-hub` vs registry `rhoai`,
    # `amq-broker-7` vs `amq7`, `kernel-module-management` vs `kmm`, `keycloak`
    # vs `rhbk`.  Merge the pull path's prefixes so operator scoping resolves
    # under either name instead of silently falling through.
    if image_ref and ctx.workload_type == "operator":
        path_ctx = parse_image_ref(image_ref)
        for p in path_ctx.extra_prefixes:
            if p not in ctx.extra_prefixes:
                ctx.extra_prefixes.append(p)
    if cpe:
        ctx.cpe = cpe

    if cpe:
        cpe_clean = re.sub(r'^cpe:[/\d.]*:*', '', cpe).strip(':')
        parts = cpe_clean.split(':')
        version_tok = parts[3]         if len(parts) > 3 else ""
        lang_tok    = parts[5].lower() if len(parts) > 5 else ""

        rhel_m = re.search(r'el(\d+)', lang_tok)
        if rhel_m:
            ctx.rhel_ver = rhel_m.group(1)
        if version_tok:
            base = ctx.display_name.split('(')[0].strip()
            ctx.display_name = f"{base} {version_tok}"
        if ctx.workload_type == "ocp" and version_tok:
            ctx.ocp_ver = version_tok

        cpe_product = parts[2].lower() if len(parts) > 2 else ""
        if ctx.workload_type == "operator" and cpe_product == "openshift":
            ctx.workload_type = "ocp"
            ctx.display_name = f"OpenShift {version_tok or ctx.ocp_ver or '4.x'}"
            ctx.extra_prefixes = []
            if version_tok:
                ctx.ocp_ver = version_tok

    # Digest pulls carry no tag and older images no CPE label — the `version`
    # label (present on 99% of images, §7c) is the remaining structural source
    # for the OCP minor.  CPE, when present, already won above.
    if ctx.workload_type == "ocp" and not ctx.ocp_ver:
        ver_m = re.match(r'v?(4\.\d+)', str(labels.get("version", "")))
        if ver_m:
            ctx.ocp_ver = ver_m.group(1)
            ctx.display_name = f"OpenShift {ctx.ocp_ver}"

    # This build's coordinates (version-release), for comparing against the
    # build tags of VEX `fixed` image PIDs (§7c: both carry Brew timestamps).
    if labels.get("version") and labels.get("release"):
        ctx.image_build = f"{labels['version']}-{labels['release']}"
    elif image_ref and not ctx.image_build:
        tag_m = re.search(r':(v?[\w.][^@/]*)$', image_ref)
        if tag_m:
            ctx.image_build = tag_m.group(1)

    if ctx.workload_type == "ocp" and name and not ctx.ocp_component:
        ctx.ocp_component = _normalize_vex_image_core(name)

    if image_ref:
        ref_base = re.sub(r'[@:][^/]*$', '', image_ref).split('/')[-1]
        rm = re.search(r'rhel(\d+)', ref_base)
        if rm:
            ctx.rhel_ver = rm.group(1)

    # The scanner read /etc/redhat-release inside the image, so it outranks every
    # naming convention above.  Without it an image carrying no labels and no
    # `-rhelN` in its path silently keeps the rhel_ver='8' dataclass default:
    # measured 92 of 13,136 RHACS scans, all `openshift-release-dev/ocp-v4.0-art-dev`
    # (labels absent, actual OS rhel:9 or rhel:10), which scopes RHEL 8 products
    # onto a RHEL 9/10 workload.
    if os_hint:
        om = re.search(r'(?:rhel|redhat)[:\-]?(\d+)', str(os_hint).lower())
        if om:
            ctx.rhel_ver = om.group(1)

    return ctx


# ══════════════════════════════════════════════════════════════════════════════
# §4  VEX product-tree identity maps (memoized once per CVE inside the VEX dict)
# ══════════════════════════════════════════════════════════════════════════════

def _build_pid_name(data: dict):
    """Lookup maps from a VEX product tree — no hardcoded labels (VEX-MODEL §4).

    Returns (pid_name, rel_parent, rhel_base_pids, pid_purl, vex_ns_map, pid_cpe,
             pid_ident):
      pid_name       {product_id → human name} from branch nodes
      rel_parent     {composite_pid → parent human name} from relationships
      rhel_base_pids parent PIDs whose name starts 'Red Hat Enterprise Linux'
      pid_purl       {product_id → purl}
      vex_ns_map     {registry_namespace → {parent product ids / cpe tokens}}
                     derived dynamically from OCI purls (bridges label namespace)
      pid_cpe        {product_id → cpe}
      pid_ident      {product_id → (pkg_name, version_release)} from the rpm
                     purl, keyed by BOTH the composite `<parent>:<component>`
                     PID that product_status uses and the bare component PID
    Memoized in data['__pid_maps__'].
    """
    cached = data.get('__pid_maps__')
    if cached is not None:
        return cached

    pid_name: dict = {}
    pid_purl: dict = {}
    pid_cpe:  dict = {}

    def _walk(branches):
        for b in branches:
            p = b.get('product', {})
            pid = p.get('product_id')
            if pid:
                pid_name[pid] = p.get('name', '')
                helper = p.get('product_identification_helper') or {}
                if helper.get('purl'):
                    pid_purl[pid] = helper['purl']
                if helper.get('cpe'):
                    pid_cpe[pid] = helper['cpe']
            _walk(b.get('branches', []))

    _walk(data.get('product_tree', {}).get('branches', []))

    # Package identity straight off the rpm purl, before any PID string parsing.
    pid_ident: dict = {}
    for pid, purl in pid_purl.items():
        name, ver = _purl_ident(purl)
        if name:
            pid_ident[pid] = (name, ver)

    rel_parent: dict = {}
    comp_to_parent_pid: dict = {}
    for rel in data.get('product_tree', {}).get('relationships', []):
        fpid   = rel.get('full_product_name', {}).get('product_id', '')
        parent = rel.get('relates_to_product_reference', '')
        comp   = rel.get('product_reference', '')
        if fpid and parent:
            rel_parent[fpid] = pid_name.get(parent, parent)
        if comp and parent:
            comp_to_parent_pid[comp] = parent
        # product_status names the composite PID; the purl hangs off the
        # component node, and relationships are the only link between them
        # (0 of 105,512 relationships carry their own identification helper).
        if fpid and comp and comp in pid_ident:
            pid_ident[fpid] = pid_ident[comp]

    rhel_base_pids = {
        pid for pid, name in pid_name.items()
        if name.startswith('Red Hat Enterprise Linux')
    }

    vex_ns_map: dict = {}
    for comp_pid, purl in pid_purl.items():
        if not purl.startswith('pkg:oci/'):
            continue
        m = re.search(r'repository_url=[^/]+/([^/&]+)', purl)
        if not m:
            continue
        oci_ns = m.group(1).lower()
        parent_pid = comp_to_parent_pid.get(comp_pid)
        if parent_pid:
            vex_ns_map.setdefault(oci_ns, set()).add(parent_pid)
            cpe = pid_cpe.get(parent_pid, '')
            if cpe:
                cpe_parts = cpe.replace('cpe:/', '').split(':')
                if len(cpe_parts) > 2:
                    vex_ns_map[oci_ns].add(cpe_parts[2])

    result = (pid_name, rel_parent, rhel_base_pids, pid_purl, vex_ns_map, pid_cpe,
              pid_ident)
    data['__pid_maps__'] = result
    return result


def _pid_label(pid: str, pid_name: dict, rel_parent: dict) -> str:
    """Human-readable label for a PID, straight from the VEX product tree."""
    if pid in rel_parent:
        return rel_parent[pid]
    parent_pid = pid.split(':')[0]
    if parent_pid in pid_name:
        return pid_name[parent_pid]
    return parent_pid


# ══════════════════════════════════════════════════════════════════════════════
# §4b/§8a  CPE prefix match, RHEL-base / version-neutral tests, scope predicate
# ══════════════════════════════════════════════════════════════════════════════

def _cpe_prefix_match(image_cpe: str, vex_cpe: str) -> bool:
    """True if the (more specific) image CPE is prefix-covered by the VEX CPE.

    Component-wise: empty VEX components are wildcards; a shorter VEX version
    prefix-covers a longer image version ('4' covers '4.12') (VEX-MODEL §4b).
    """
    def _parse_cpe(cpe: str) -> list:
        cpe = re.sub(r'^cpe:[/\d.]*:*', '', cpe).strip(':')
        return [p for p in cpe.split(':')]

    img_parts = _parse_cpe(image_cpe)
    vex_parts = _parse_cpe(vex_cpe)
    while vex_parts and vex_parts[-1] == '':
        vex_parts.pop()
    if not vex_parts:
        return False
    if len(vex_parts) < 3 or len(img_parts) < 3:
        return False
    for i, vex_comp in enumerate(vex_parts):
        if i >= len(img_parts):
            return False
        if not vex_comp:
            continue
        if i == 3:   # version position
            img_ver_parts = img_parts[i].split('.')
            vex_ver_parts = vex_comp.split('.')
            if img_ver_parts[:len(vex_ver_parts)] != vex_ver_parts:
                return False
        elif vex_comp.lower() != img_parts[i].lower():
            return False
    return True


def _is_rhel_base_product(pid: str, rhel_ver: str, rhel_base_pids: set) -> bool:
    """True only for a RHEL base repo PID of the given major (VEX-MODEL §1a/§8a).

    Qualifying parent PIDs come from product-tree names ('Red Hat Enterprise
    Linux …') — no hardcoded stream names (AppStream/BaseOS/CRB/…).
    """
    parent_pid = pid.split(':')[0]
    if parent_pid not in rhel_base_pids and pid not in rhel_base_pids:
        return False
    pid_lower = pid.lower()
    if f'enterprise_linux_{rhel_ver}' in pid_lower:
        return True
    if re.search(rf'\.el{rhel_ver}[_.\-a-z]', pid) or re.search(rf'\.el{rhel_ver}$', pid):
        return True
    if re.search(rf'^[a-zA-Z]+-{rhel_ver}[.\-]', pid):
        return True
    return False


def _is_any_rhel_ver_product(pid: str, rhel_ver: str) -> bool:
    """Broader: any PID mentioning this RHEL major, incl. layered/middleware."""
    pid_lower = pid.lower()
    if f'enterprise_linux_{rhel_ver}' in pid_lower:
        return True
    if f'_rhel_{rhel_ver}' in pid_lower or f'_rhel{rhel_ver}' in pid_lower:
        return True
    if re.search(rf'\.el{rhel_ver}[_.\-a-z]', pid) or re.search(rf'\.el{rhel_ver}$', pid):
        return True
    if re.search(rf'^[a-zA-Z]+-{rhel_ver}[.\-]', pid):
        return True
    if re.search(rf'^{rhel_ver}[A-Za-z]', pid):
        return True
    return False


def _is_version_neutral_product(pid: str) -> bool:
    """True when a PID carries no RHEL/el version marker at all (VEX-MODEL §1d).

    Version-agnostic product PIDs (…platform_4:openshift-clients) cannot
    contradict the workload's RHEL version → admissible as related evidence.
    """
    if re.search(r'[.+]el\d', pid):
        return False
    if re.search(r'_rhel_?\d', pid.lower()):
        return False
    if 'enterprise_linux_' in pid.lower():
        return False
    return True


@functools.lru_cache(maxsize=4096)
def _prefix_pattern(prefix_lower: str):
    """Token-boundary matcher for a catalog/namespace prefix."""
    return re.compile(rf'(?:^|[^a-z0-9]){re.escape(prefix_lower)}(?:[^a-z0-9]|$)')


def _prefix_matches_pid(prefix: str, pid_lower: str) -> bool:
    """Does a catalog/namespace prefix name this PID's product?

    Path prefixes ('rhoai/', 'registry.redhat.io/rhoai/') keep substring
    semantics — the trailing '/' already bounds them.  Bare tokens must match on
    a token boundary, because the map contributes very short CPE tokens ('ai',
    'dns', 'eap', 'mcg', 'ocs', 'odf', 'ptp', 'sbd', …) and a raw substring test
    lets them collide with unrelated products: 'ai' matches the *stream name* in
    `BaseOS-8.10.0.Z.M(AI)N.EUS`, which pulled every RHEL major's base repos into
    an operator workload's scope.  A cross-major fix then wins the §6b GA
    comparison an el8 package can never satisfy (systemd 239-78.el8 vs the el9
    fix 250-12.el9_1.1), making the finding permanently POSITIVE.  Boundary
    matching still matches what the token is for — 'ai' in
    `Red Hat OpenShift AI 2.25`.
    """
    p = prefix.lower()
    if not p:
        return False
    if p.endswith('/'):
        return p in pid_lower
    return bool(_prefix_pattern(p).search(pid_lower))


def _pid_in_scope(pid: str, ctx: WorkloadContext, pid_name: dict,
                  rhel_base_pids: set, vex_ns_map: Optional[dict] = None,
                  pid_cpe: Optional[dict] = None) -> bool:
    """Is a VEX product_id in scope for the workload? (VEX-MODEL §8a).

      ubi      : only RHEL base repos of the workload's RHEL major
      ocp      : RHEL base repos + 'Red Hat OpenShift Container Platform <v>'
                 (version prefix-matched) + image-CPE↔VEX-CPE prefix match +
                 any product mentioning the workload's RHEL major (Fast Datapath…)
      operator : RHEL base repos + catalog prefixes (ctx.extra_prefixes) +
                 dynamic registry-namespace→product map from OCI purls
    Memoized per (workload identity, pid) in a slot carried by vex_ns_map.
    """
    _cache = None
    if isinstance(vex_ns_map, dict):
        _fp = (ctx.workload_type, ctx.rhel_ver, ctx.ocp_ver, ctx.image_ns,
               ctx.image_name, ctx.ocp_component, ctx.cpe,
               tuple(ctx.extra_prefixes))
        _slot = vex_ns_map.get('__scope_cache__')
        if _slot is None or _slot[0] != _fp:
            _slot = (_fp, {})
            vex_ns_map['__scope_cache__'] = _slot
        _cache = _slot[1]
        _hit = _cache.get(pid)
        if _hit is not None:
            return _hit

    def _memo(result: bool) -> bool:
        if _cache is not None:
            _cache[pid] = result
        return result

    if _is_rhel_base_product(pid, ctx.rhel_ver, rhel_base_pids):
        return _memo(True)

    if ctx.workload_type == "ubi":
        return _memo(False)

    if ctx.workload_type == "ocp":
        parent_pid  = pid.split(':')[0]
        parent_name = pid_name.get(parent_pid) or pid_name.get(pid, '')
        if 'openshift container platform' in parent_name.lower():
            effective_ver = ctx.ocp_ver or "4"
            name_ver = parent_name.split()[-1]
            c = effective_ver.split('.')
            n = name_ver.split('.')
            return _memo(c[:len(n)] == n)
        if pid_cpe and ctx.cpe:
            vex_parent_cpe = pid_cpe.get(parent_pid, '')
            if vex_parent_cpe and _cpe_prefix_match(ctx.cpe, vex_parent_cpe):
                return _memo(True)
        if _is_any_rhel_ver_product(pid, ctx.rhel_ver):
            return _memo(True)
        return _memo(False)

    # operator
    pid_lower = pid.lower()
    for prefix in ctx.extra_prefixes:
        if _prefix_matches_pid(prefix, pid_lower):
            return _memo(True)
    if vex_ns_map and ctx.image_ns:
        parent_pid = pid.split(':')[0]
        ns_products = vex_ns_map.get(ctx.image_ns.lower(), set())
        if parent_pid in ns_products:
            return _memo(True)
        for prod_id in ns_products:
            if _prefix_matches_pid(prod_id, pid_lower):
                return _memo(True)
    return _memo(False)


# ══════════════════════════════════════════════════════════════════════════════
# §4a/§8 3a  Image (OCI) identity — purl / path / digest matching
# ══════════════════════════════════════════════════════════════════════════════

def _build_image_purl(image_ref: Optional[str], image_name_label: Optional[str] = None):
    """OCI identity candidates for the workload image (VEX-MODEL §4a/§7d).

    Returns (candidates, sha) where candidates are (repository_url, image_name)
    pairs from (1) the pull reference — authoritative — and (2) the `name` label.
    No namespace rewriting: callers match by exact repository_url first, then by
    pkg:oci/<name> equality.
    """
    candidates = []
    sha = None
    if image_ref:
        m = re.search(r'@sha256:([a-f0-9]+)', image_ref)
        sha = m.group(1) if m else None
        bare = re.sub(r'[@:][^/]*$', '', image_ref)
        parts = bare.split('/')
        if len(parts) >= 2:
            candidates.append((bare, parts[-1]))
    if image_name_label and '/' in image_name_label:
        name = image_name_label.split('/')[-1]
        repo = f"registry.redhat.io/{image_name_label}"
        if all(c[0] != repo for c in candidates):
            candidates.append((repo, name))
    return candidates, sha


def _purl_matched_leaf_pids(pid_purl: dict, candidates: list) -> set:
    """VEX component PIDs whose OCI purl matches an image candidate (§4a/§8 3a).

    Exact repository_url match wins; otherwise pkg:oci/<name> equality bridges
    Brew↔registry namespaces without a hardcoded map.
    """
    if not candidates:
        return set()
    repos = {c[0] for c in candidates}
    names = {c[1] for c in candidates}
    by_repo, by_name = set(), set()
    for pid, purl in pid_purl.items():
        if not purl.startswith('pkg:oci/'):
            continue
        m = re.match(r'pkg:oci/([^?@]+)', purl)
        pname = m.group(1) if m else ''
        last = pname.split('/')[-1]
        r = re.search(r'repository_url=([^&]+)', purl)
        if r:
            # Two purl eras coexist: repository_url may be the full repo path
            # or the namespace only (image name lives in the purl name) —
            # compose the effective repo so both compare exactly.
            repo = r.group(1)
            if last and not repo.endswith('/' + last):
                repo = f"{repo}/{last}"
            if repo in repos:
                by_repo.add(pid)
                continue
        if pname in names or (last and last in names):
            by_name.add(pid)
    return by_repo if by_repo else by_name


# ══════════════════════════════════════════════════════════════════════════════
# §3f/§7  Component name resolution: binary→source, maven, SBOM alias, verify
# ══════════════════════════════════════════════════════════════════════════════

# All CSAF/VEX flag labels that mean the product is NOT affected (VEX-MODEL §5b).
_NOT_AFFECTED_FLAGS = {
    'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'component_not_present',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist',
}


def wire_rpm_owners(df, ctx, owners: dict) -> None:
    """Give matching and emission the rpm identity of go-binary components.

    Red Hat assesses golang CVEs against the VENDORING rpm (rhel9:buildah), not
    the module purl the scanner reports — without this link those verdicts are
    invisible: an affected rpm looks "not listed" (⇒ false positive) and a
    not_affected rpm never reaches trivy's rpm-level finding.  It is also what
    lets openvex.statements_from_df see a divergent group — a Go component
    cleared while its vendoring rpm is still open — and withhold the statement.

    - df['OWNER_RPM'] = 'name@version-release' per non-OS row (emitter bridge)
    - ctx.sbom_src_map[component] = rpm name (engine _resolve_comp alias); a
      component seen in binaries of two different rpms stays unmapped — one
      verdict row can't represent diverging owners.

    Path forms differ by producer: syft records absolute paths (`/usr/bin/oc`),
    RHACS component locations are relative (`usr/bin/oc`), so both are indexed.
    """
    if df is None or df.empty or not owners:
        return
    norm = {}
    for path, owner in owners.items():
        p = str(path)
        norm[p] = owner
        norm['/' + p.lstrip('/')] = owner
        norm[p.lstrip('/')] = owner

    df['OWNER_RPM'] = df.apply(
        lambda r: '{}@{}'.format(*norm[str(r.get('LOCATION', ''))])
        if str(r.get('SOURCE', '')).strip().upper() != 'OS'
        and str(r.get('LOCATION', '')) in norm else '', axis=1)
    src_map, conflict = {}, set()
    for _, r in df.iterrows():
        owner = str(r.get('OWNER_RPM', '') or '')
        if not owner:
            continue
        comp, name = str(r['COMPONENT']), owner.split('@')[0]
        if src_map.get(comp, name) != name:
            conflict.add(comp)
        src_map.setdefault(comp, name)
    for c in conflict:
        src_map.pop(c, None)
    ctx.sbom_src_map = {**src_map, **(ctx.sbom_src_map or {})}


def rpm_source_map_from_sbom(sbom_path: str) -> dict:
    """binary rpm name → source rpm name, from a syft-json SBOM's `upstream=`.

    The authoritative binary→source link.  Without it `libsmartcols` never
    reaches `util-linux`'s statements and reads as "not listed as affected" — a
    FALSE POSITIVE for a package Red Hat lists as known_affected.
    """
    try:
        with open(sbom_path) as fh:
            doc = json.load(fh)
    except Exception:
        return {}
    out = {}
    for a in doc.get('artifacts', []):
        if a.get('type') != 'rpm' or not a.get('name'):
            continue
        m = re.search(r'upstream=([^&]+?)-[^-]+-[^-]+\.src\.rpm', a.get('purl') or '')
        if m and m.group(1) != a['name']:
            out[a['name']] = m.group(1)
    return out


def rpm_file_owners_from_sbom(sbom_path: str) -> dict:
    """path → ('rpm name', 'version-release') from a syft-json SBOM.

    Mirrors adapters.grype.rpm_file_owners so the RHACS path can build the same
    ownership link from an SBOM already on disk, without a scanner run.
    """
    try:
        with open(sbom_path) as fh:
            doc = json.load(fh)
    except Exception:
        return {}
    owners = {}
    for a in doc.get('artifacts', []):
        if a.get('type') != 'rpm':
            continue
        name = a.get('name', '')
        ver = re.sub(r'^\d+:', '', str(a.get('version', '')))
        if not name or not ver:
            continue
        for f in (a.get('metadata') or {}).get('files') or []:
            path = f.get('path') if isinstance(f, dict) else str(f)
            if path:
                owners[path] = (name, ver)
    return owners


def _resolve_comp(comp: str, ctx: WorkloadContext) -> set:
    """Candidate package names for matching VEX PIDs (VEX-MODEL §7a).

    RPM binary→source via SBOM (`python3-urllib3`→`python-urllib3`) and Maven
    groupId:artifactId → bare artifactId (`com.nimbusds:nimbus-jose-jwt` →
    `nimbus-jose-jwt`).  The Maven split requires ':' but not '/' (avoids Go
    module paths / image refs).
    """
    names = {comp}
    src = ctx.sbom_src_map.get(comp) if ctx.sbom_src_map else None
    if src and src != comp:
        names.add(src)
    if ':' in comp and '/' not in comp and not comp.startswith('cpe:'):
        artifact = comp.rsplit(':', 1)[-1]
        if artifact and artifact != comp:
            names.add(artifact)
    return names


def _src_alias_names(data: dict, comp: str, found_v: str, srpm: str = '') -> set:
    """Source-RPM aliases for a binary subpackage, derived from the VEX (§3f/§8 5s).

    Red Hat sometimes tracks only the source package (`ceph`, `perl`) while the
    scanner reports a binary subpackage (`ceph-mon`, `perl-libs`).  A `.src` PID
    whose name is a dash-prefix of the component AND whose version-release equals
    the installed one (or which is a version-less `.src` wildcard) is the source
    that built it.

    The shared version-release is the load-bearing structural signal: a bare
    dash-prefix is NOT sufficient, because unrelated module packages share a
    prefix with an interpreter (`python3-urllib3` vs `python3`,
    `nodejs-nodemon` vs `nodejs`) yet carry a different VR and are built from a
    different source.  (VEX-MODEL §9.1 proposed dropping the VR check as a
    "latent fragility"; on the corpus it is not latent — dropping it
    misattributes the interpreter's fixed NEVRA to those module packages, so the
    check is retained.  The authoritative binary→source map is still the SBOM's
    GENERATED_FROM, applied in _resolve_comp.)
    """
    src_vr = data.get('__src_vr__')
    if src_vr is None:
        src_vr = {}
        pid_ident = _build_pid_name(data)[6]
        for vuln in data.get('vulnerabilities', []):
            ps = vuln.get('product_status', {})
            for st in ('known_affected', 'fixed', 'known_not_affected',
                       'under_investigation'):
                for pid in ps.get(st, []):
                    base = pid.split('::')[0]
                    if not base.endswith('.src'):
                        continue
                    name, vr = _pkg_from_pid(pid, pid_ident)
                    if name:
                        # vr is None for a version-less product-level .src PID
                        # (red_hat_ceph_storage:ceph.src) — record as wildcard.
                        src_vr.setdefault(name, set()).add(vr)
        data['__src_vr__'] = src_vr
    vr = found_v.split(':', 1)[-1] if ':' in found_v else found_v
    aliases = {src for src, vrs in src_vr.items()
               if comp.startswith(src + '-') and (vr in vrs or None in vrs)}

    # When the SOURCE package is known for certain — the rpm purl's `upstream=`
    # qualifier names it — a dash-prefix guess must never override it.  The VR
    # gate above cannot catch this on its own: a version-less `.src` PID is a
    # wildcard, so ANY `python3-*` package matches `python3` regardless of its
    # own version.  That misattributed python3's fixed NEVRA to
    # python3-chardet 4.0.0-5.el9 ("4.0.0 >= 3.9.21" → FALSE POSITIVE) even
    # though CVE-2024-0397 lists chardet as known_affected and ships no chardet
    # fix at all.  chardet is built from python-chardet, not python3.
    if srpm:
        aliases = {a for a in aliases if a == srpm}
        aliases.add(srpm)
    return aliases


def _sbom_note(comp: str, version: str, ctx: WorkloadContext) -> str:
    """SBOM verification fragment for an OS/RPM component (VEX-MODEL §7f).

    Relates the scanner-reported version to the SBOM inventory via RPM compare.
    '' when no SBOM is loaded.
    """
    if not ctx.sbom_packages:
        return ''
    names = _resolve_comp(comp, ctx)
    for name in names:
        sbom_vers = ctx.sbom_packages.get(name)
        if sbom_vers is None:
            continue
        if not version or str(version) in ('nan', 'None'):
            return f"{comp} (in SBOM, version not reported)"
        sbom_list = sorted(sbom_vers)
        best_sbom = sbom_list[0]
        for sv in sbom_list[1:]:
            try:
                i, f = _normalize_epoch(sv, best_sbom)
                if compare_versions(i, f) > 0:
                    best_sbom = sv
            except Exception:
                pass
        try:
            cmp_scan, cmp_sbom = _normalize_epoch(version, best_sbom)
            cmp = compare_versions(cmp_scan, cmp_sbom)
        except Exception:
            cmp = None
        if cmp == 0:
            return f"{comp}-{version} (SBOM verified)"
        elif cmp is not None and cmp > 0:
            return f"{comp}-{version} (scanner reports newer than SBOM: {best_sbom})"
        elif cmp is not None and cmp < 0:
            return f"{comp}-{version} (SBOM has newer: {best_sbom})"
        return f"{comp}-{version} (SBOM has: {best_sbom})"
    return f"{comp}-{version} (not in SBOM)"


# ══════════════════════════════════════════════════════════════════════════════
# §5c/§5d/§5e/§1g  Threats, remediations, catch-all, product summary
# ══════════════════════════════════════════════════════════════════════════════

def _build_pid_severity_map(data: dict) -> dict:
    """{product_id → impact title} from per-product threats (VEX-MODEL §5c)."""
    cached = data.get('__pid_severity__')
    if cached is not None:
        return cached
    pid_severity: dict = {}
    for vuln in data.get('vulnerabilities', []):
        for threat in vuln.get('threats', []):
            if threat.get('category') != 'impact' or not threat.get('details'):
                continue
            det = threat['details'].title()
            for tpid in threat.get('product_ids', []):
                pid_severity[tpid] = det
    data['__pid_severity__'] = pid_severity
    return pid_severity


def _rem_map(data: dict) -> dict:
    """{product_id → [(category, details), …]} from remediations (VEX-MODEL §5d)."""
    rem_map = data.get('__rem_map__')
    if rem_map is None:
        rem_map = {}
        for vuln in data.get('vulnerabilities', []):
            for rem in vuln.get('remediations', []):
                cat = rem.get('category', '')
                det = (rem.get('details') or '').strip()
                for pid in rem.get('product_ids', []):
                    rem_map.setdefault(pid, []).append((cat, det))
        data['__rem_map__'] = rem_map
    return rem_map


def _is_catchall_not_affected(data: dict) -> bool:
    """True if a bare-vendor catch-all PID marks everything not-affected (§1g/§8 1).

    Detects vendor-level nodes (`red_hat_products`, or any node whose CPE is the
    bare `cpe:/a:redhat` single vendor token) appearing in known_not_affected or
    a not-affected flag.
    """
    catchall_pids: set = set()
    for branch in data.get('product_tree', {}).get('branches', []):
        prod = branch.get('product', {})
        helper = prod.get('product_identification_helper') or {}
        cpe_str = str(helper.get('cpe', ''))
        cpe_parts = [p for p in cpe_str.split(':') if p not in ('', 'cpe', '/a', '/o', '/h')]
        if len(cpe_parts) == 1 and cpe_parts[0].lower() in ('redhat', 'red_hat'):
            pid = prod.get('product_id', '')
            if pid:
                catchall_pids.add(pid)
    catchall_pids.add('red_hat_products')

    for vuln in data.get('vulnerabilities', []):
        ps = vuln.get('product_status', {})
        flags = vuln.get('flags', [])
        catchall_not_affected = catchall_pids & (
            set(ps.get('known_not_affected', [])) |
            {pid
             for flag in flags
             if flag.get('label') in _NOT_AFFECTED_FLAGS
             for pid in flag.get('product_ids', [])}
        )
        if catchall_not_affected:
            return True
    return False


def _summarise_vex_products(data, pid_name: dict, rel_parent: dict):
    """(affected, fixed, not_affected, investigating) product labels, sorted."""
    affected, fixed, not_affected, investigating = set(), set(), set(), set()
    for vuln in data.get('vulnerabilities', []):
        ps    = vuln.get('product_status', {})
        flags = vuln.get('flags', [])
        for pid in ps.get('known_affected', []):
            affected.add(_pid_label(pid, pid_name, rel_parent))
        for pid in ps.get('fixed', []):
            fixed.add(_pid_label(pid, pid_name, rel_parent))
        for pid in ps.get('known_not_affected', []):
            not_affected.add(_pid_label(pid, pid_name, rel_parent))
        for pid in ps.get('under_investigation', []):
            investigating.add(_pid_label(pid, pid_name, rel_parent))
        for flag in flags:
            if flag.get('label') in _NOT_AFFECTED_FLAGS:
                for pid in flag.get('product_ids', []):
                    not_affected.add(_pid_label(pid, pid_name, rel_parent))
    return sorted(affected), sorted(fixed), sorted(not_affected), sorted(investigating)


# ══════════════════════════════════════════════════════════════════════════════
# §8d  Severity, state and fix — read from the DECISIVE match
# ══════════════════════════════════════════════════════════════════════════════
#
# The pipeline records the decisive product_status PID(s) in a small `dec` dict:
#     {'kind': str, 'pids': [full_pid, …], 'status': str, 'fix_set': bool}
# Severity/state are then read from that same match — never an independent
# search, never by parsing the justification text.

_RHACS_SEVERITY_MAP = {
    'CRITICAL_VULNERABILITY_SEVERITY':  'Critical',
    'HIGH_VULNERABILITY_SEVERITY':      'Important',
    'IMPORTANT_VULNERABILITY_SEVERITY': 'Important',
    'MODERATE_VULNERABILITY_SEVERITY':  'Moderate',
    'MEDIUM_VULNERABILITY_SEVERITY':    'Moderate',
    'LOW_VULNERABILITY_SEVERITY':       'Low',
    'CRITICAL':  'Critical', 'HIGH': 'Important', 'IMPORTANT': 'Important',
    'MEDIUM':    'Moderate',  'MODERATE': 'Moderate', 'LOW': 'Low',
}

_SEV_ORDER = {'Critical': 0, 'Important': 1, 'Moderate': 2, 'Low': 3}


def _pid_threat_severity(pid: str, pid_severity: dict):
    """Impact severity of a PID (direct key, then leaf-suffix match)."""
    if pid in pid_severity:
        return pid_severity[pid]
    for spid, sev in pid_severity.items():
        if spid.endswith(':' + pid):
            return sev
    return None


def _severity_fallback(data, comp, ctx, pid_name, rhel_base_pids, vex_ns_map,
                       pid_severity, row, pid_cpe, pid_purl) -> str:
    """Base-severity chain used only when the decisive PID has no impact threat
    (VEX-MODEL §8d, tiers 1-8).

    image-level PID impact → component-name PID impact → highest in-scope
    known_affected/fixed impact → document aggregate_severity → any impact
    threat → CVSS baseSeverity → RHACS scan severity.
    """
    severity = "UNKNOWN"
    names_to_match = _resolve_comp(comp, ctx)
    pid_ident = _build_pid_name(data)[6]

    # OCI-purl match — when the image's OCI purl matches a VEX PID (even one not
    # decisive for the verdict, e.g. a not-listed component), use that PID's
    # threat (own digest > generic > uniform other build).  Keeps parity with
    # the previous severity for verdicts that carry no decisive PID.
    if pid_purl and ctx.workload_type in ("ocp", "operator"):
        _label_name = f"{ctx.image_ns}/{ctx.image_name}" if (ctx.image_ns and ctx.image_name) else None
        _candidates, _img_sha = _build_image_purl(ctx.image_ref, _label_name)
        _own_sha_set = _own_shas(ctx)

        def _leaf_severity(_pid):
            if _pid in pid_severity:
                return pid_severity[_pid]
            for _spid, _sev in pid_severity.items():
                if _spid.endswith(':' + _pid):
                    return _sev
            return None

        _matched = _purl_matched_leaf_pids(pid_purl, _candidates)
        _own = [p for p in _matched if any(sh in p for sh in _own_sha_set)]
        _generic = [p for p in _matched if '@sha256:' not in p]
        for _pid in _own + _generic:
            _sev = _leaf_severity(_pid)
            if _sev:
                severity = _sev
                break
        if severity == "UNKNOWN":
            _other_sevs = {s for s in
                           (_leaf_severity(p) for p in _matched if '@sha256:' in p and p not in _own)
                           if s}
            if len(_other_sevs) == 1:
                severity = _other_sevs.pop()

    # image-level PID (generic, no digest) — most specific for container triage
    if severity == "UNKNOWN" and ctx.workload_type in ("ocp", "operator"):
        img_comp = ctx.ocp_component or (
            _normalize_vex_image_core(ctx.image_name) if ctx.image_name else None)
        if img_comp:
            img_norm = _normalize_ocp_component(img_comp)
            for pid, sev in pid_severity.items():
                if '@sha256:' in pid:
                    continue
                if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map, pid_cpe=pid_cpe):
                    continue
                tpkg, _ = _pkg_from_pid(pid, pid_ident)
                if not tpkg:
                    continue
                if '/' in tpkg and _normalize_vex_image_core(tpkg) == img_comp:
                    severity = sev
                    break
                if '/' not in tpkg and _normalize_ocp_component(tpkg) == img_norm:
                    severity = sev
                    break

    if severity == "UNKNOWN":
        for pid, sev in pid_severity.items():
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map, pid_cpe=pid_cpe):
                continue
            tpkg, _ = _pkg_from_pid(pid, pid_ident)
            if tpkg and tpkg in names_to_match:
                severity = sev
                break

    if severity == "UNKNOWN":
        aff_sevs = set()
        for vuln in data.get('vulnerabilities', []):
            for st in ('known_affected', 'fixed'):
                for pid in vuln.get('product_status', {}).get(st, []):
                    if pid in pid_severity and _pid_in_scope(
                            pid, ctx, pid_name, rhel_base_pids, vex_ns_map, pid_cpe=pid_cpe):
                        aff_sevs.add(pid_severity[pid])
        if aff_sevs:
            severity = min(aff_sevs, key=lambda s: _SEV_ORDER.get(s, 9))

    if severity == "UNKNOWN":
        agg = data.get('document', {}).get('aggregate_severity', {}).get('text', '')
        if agg and agg.strip().lower() not in ('', 'none'):
            severity = agg.title()

    if severity == "UNKNOWN":
        for vuln in data.get('vulnerabilities', []):
            for threat in vuln.get('threats', []):
                if threat.get('category') == 'impact' and threat.get('details'):
                    severity = threat['details'].title()
                    break
            if severity != "UNKNOWN":
                break

    if severity == "UNKNOWN":
        for vuln in data.get('vulnerabilities', []):
            for score in vuln.get('scores', []):
                cvss = score.get('cvss_v3') or score.get('cvss_v2') or {}
                base = cvss.get('baseSeverity', '').upper()
                if base:
                    severity = {'CRITICAL': 'Critical', 'HIGH': 'Important',
                                'MEDIUM': 'Moderate', 'LOW': 'Low'}.get(base, base.title())
                    break
            if severity != "UNKNOWN":
                break

    if severity in ("UNKNOWN", "None", ""):
        mapped = _RHACS_SEVERITY_MAP.get(str(row.get('SEVERITY', '')).strip().upper())
        if mapped:
            severity = mapped
    if severity in ("UNKNOWN", "None", "", "nan"):
        severity = "Unknown"
    return severity


def _severity_from_decisive(data, dec, ctx, comp, row, pid_severity, pid_name,
                            rhel_base_pids, vex_ns_map, pid_cpe, pid_purl) -> str:
    """Severity from the decisive PID's impact threat (VEX-MODEL §8d).

    Priority within the decisive set: our own image digest > generic (no-digest)
    > a rating uniform across other builds.  Falls back to the base-severity
    chain only when the decisive PID carries no impact threat.
    """
    pids = dec.get('pids') or []
    if pids:
        our_shas = _own_shas(ctx)
        own      = [p for p in pids if any(sh in p for sh in our_shas)]
        generic = [p for p in pids if '@sha256:' not in p]
        for p in own + generic:
            s = _pid_threat_severity(p, pid_severity)
            if s:
                return s
        rest = [p for p in pids if p not in own and p not in generic]
        rest_sevs = {s for s in (_pid_threat_severity(p, pid_severity) for p in rest) if s}
        if len(rest_sevs) == 1:
            return rest_sevs.pop()
    return _severity_fallback(data, comp, ctx, pid_name, rhel_base_pids,
                              vex_ns_map, pid_severity, row, pid_cpe, pid_purl)


# FALSE-POSITIVE kinds whose meaning is "the build already carries the fix"
# (state → "Fixed"); every other clear verdict means "Not affected".
_FP_FIXED_KINDS = {'digest_fixed', 'rpm_fixed_pass', 'errata_fixed', 'img_sha_fixed'}

# Decision kinds whose verdict rests on the ABSENCE of a statement (or on
# statements about other products only) — nothing in the VEX names the scanned
# product/image/component.  Their FALSE POSITIVEs are triage-display verdicts;
# openvex.py must not publish a not_affected/fixed claim Red Hat never stated.
_UNSTATED_KINDS = {
    'rpm_not_listed', 'nonrpm_not_listed', 'img_not_listed',
    'ft_other', 'ft_novex_scoped', 'ft_operator_novex', 'ft_not_affected',
    'ft_clear', 'ft_rhel_clear',   # family/platform clear: statements exist
    # but name other packages — the ft_* fallthrough fires only after every
    # component/image identity rung failed, so nothing names what we scanned
    'errata_newer',                # §5g newer-than-newest-fix inference
}


def _state_from_decisive(verdict, dec, data, ctx, pid_name, rhel_base_pids,
                         vex_ns_map, pid_cpe) -> str:
    """Red Hat page State, read from the decisive match (VEX-MODEL §8d).

    FALSE POSITIVE → "Fixed" (build carries the fix) / "Not affected".
    POSITIVE → the decisive PID's own remediation: `no_fix_planned` details
    verbatim ("Will not fix"/"Out of support scope"); `none_available` →
    "Fix deferred"/"Affected"; `vendor_fix` or a concrete fix → "Fix available";
    `under_investigation` status → "Under investigation".  Falls back to the
    in-scope known_affected remediations when the decisive PID carries none.
    """
    kind = dec.get('kind', '')
    if data is None or kind == 'vex_missing':
        return 'Unknown'
    if '✅' in verdict:
        if kind in _FP_FIXED_KINDS or dec.get('status') == 'fixed':
            return 'Fixed'
        return 'Not affected'

    # POSITIVE
    if dec.get('status') == 'under_investigation' or kind.endswith('_ui'):
        return 'Under investigation'

    rem_map = _rem_map(data)

    def _scan(pids):
        no_fix = none_avail = has_vendor = None
        for pid in pids:
            for cat, det in rem_map.get(pid, []):
                if cat == 'no_fix_planned' and no_fix is None:
                    no_fix = det or 'Will not fix'
                elif cat == 'none_available' and none_avail is None:
                    none_avail = det or 'Affected'
                elif cat == 'vendor_fix':
                    has_vendor = True
        return no_fix, none_avail, has_vendor

    no_fix, none_avail, has_vendor = _scan(dec.get('pids') or [])
    if no_fix:
        return no_fix
    if none_avail:
        return 'Fix deferred' if 'defer' in none_avail.lower() else none_avail
    if has_vendor or dec.get('fix_set'):
        return 'Fix available'

    scoped_ka = []
    for vuln in data.get('vulnerabilities', []):
        for pid in vuln.get('product_status', {}).get('known_affected', []):
            if _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map, pid_cpe=pid_cpe):
                scoped_ka.append(pid)
    no_fix, none_avail, _ = _scan(scoped_ka)
    if no_fix:
        return no_fix
    if none_avail:
        return 'Fix deferred' if 'defer' in none_avail.lower() else none_avail
    return 'Affected'


# ══════════════════════════════════════════════════════════════════════════════
# §6  RPM path — component in scope (rung 5), related (8), absent (9)
# ══════════════════════════════════════════════════════════════════════════════

def _rpm_candidates(vuln, ctx, maps, names, found_v, comp=None):
    """One walk over a vuln's product_status + not-affected flags.

    Yields [(status, pid, pkg_ver)] for PIDs that are in scope, module-stream
    compatible and name-matching, in status priority order KNA > fixed > KA > UI
    (VEX-MODEL §8b rung 5); flag PIDs are folded into known_not_affected (§5b).
    JSON list order is preserved within each status so the first candidate is the
    same representative the legacy first-match loop selected — except that a PID
    naming the component exactly ranks before src-alias matches within its
    status: a package with its own statement (own SRPM, own remediation) must be
    decisive over its alias source (openssl-fips-provider vs openssl).
    """
    pid_name, rel_parent, rhel_base_pids, pid_purl, vex_ns_map, pid_cpe, pid_ident = maps
    ps = vuln.get('product_status', {})
    flags = vuln.get('flags', [])
    out = []

    def _emit(status, pid):
        if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map, pid_cpe=pid_cpe):
            return
        if not _module_stream_compatible(pid, found_v):
            return
        name, ver = _pkg_from_pid(pid, pid_ident)
        if name in names:
            out.append((status, pid, ver, name))

    for pid in ps.get('known_not_affected', []):
        _emit('known_not_affected', pid)
    for flag in flags:
        if flag.get('label') in _NOT_AFFECTED_FLAGS:
            for pid in flag.get('product_ids', []):
                _emit('known_not_affected', pid)
    for pid in ps.get('fixed', []):
        _emit('fixed', pid)
    for pid in ps.get('known_affected', []):
        _emit('known_affected', pid)
    for pid in ps.get('under_investigation', []):
        _emit('under_investigation', pid)
    if comp:
        rank = {'known_not_affected': 0, 'fixed': 1, 'known_affected': 2,
                'under_investigation': 3}
        out.sort(key=lambda t: (rank[t[0]], 0 if t[3] == comp else 1))
    return [(s, p, v) for s, p, v, _n in out]


def _upstream_newer_than_all(installed: str, fixes) -> bool:
    """Is *installed* strictly newer than every fix on EPOCH:VERSION alone?

    Cross-stream RELEASE comparison is meaningless — RHEL minor branches number
    their releases independently, so `expat-2.5.0-6.el9_8.1` vs the 9.0 E4S
    backport `expat-2.2.10-12.el9_0.4` compares 6 < 12 and calls the newer branch
    older.  That is why §6b forbids it.  The upstream VERSION carries no such
    confound: a build whose version is strictly greater than the version a fix
    shipped in cannot be missing that fix, whatever branch either came from.

    Deliberately strict.  Equal versions differing only in release (2.2.10-12 vs
    2.2.10-14) fall back to the release confound and stay POSITIVE.
    """
    seen = False
    for fix_v in fixes:
        try:
            inst, fix = _normalize_epoch(installed, fix_v)
        except Exception:
            return False
        if _rpmvercmp(inst.partition('-')[0], fix.partition('-')[0]) <= 0:
            return False
        seen = True
    return seen


def _compare_fixed(found_v, unique_fixed, comp, ctx, rpm_rhel, dec, fix_pid_by_ver):
    """Stream-aware RPM version comparison against VEX fixed NEVRAs (VEX-MODEL §6b).

    A minor-stream install (el9_4) compares only against same-minor fixes; a fix
    that exists but not yet in the installed stream stays POSITIVE; a GA install
    must be ≥ every stream fix.  Records the decisive fixed PID in *dec* and
    returns (verdict, fix, note).
    """
    installed_minor = _detect_rhel_minor(found_v)
    sn = _sbom_note(comp, found_v, ctx) if rpm_rhel else ''

    def _decide(ver, kind, fix_set):
        dec['kind'], dec['status'], dec['fix_set'] = kind, 'fixed', fix_set
        pid = fix_pid_by_ver.get(ver)
        dec['pids'] = [pid] if pid else []

    if installed_minor:
        same_stream = [v for v in unique_fixed if _detect_rhel_minor(v) == installed_minor]
        if same_stream:
            compare_fixes = same_stream
        elif _upstream_newer_than_all(found_v, unique_fixed):
            # No erratum for our stream because our stream never needed one: we
            # carry a strictly newer upstream version than any branch the fix
            # shipped in.  Without this, every package that moved forward a
            # release stays POSITIVE forever against a backport to a frozen EUS
            # branch — expat 2.5.0 on 9.8 against 2.2.10-12.el9_0.4 (2013).
            ref = unique_fixed[0]
            _decide(ref, 'rpm_fixed_newer_upstream', False)
            prefix = f"{sn}; " if sn else ''
            return ("✅ FALSE POSITIVE", ref,
                    f"{prefix}Installed {found_v} is a newer upstream version "
                    f"than every fix Red Hat shipped ({ref}).")
        else:
            best_ref = unique_fixed[0]
            _decide(best_ref, 'rpm_fixed_fail', True)
            prefix = f"{sn}; " if sn else ''
            return ("❌ POSITIVE", best_ref,
                    f"{prefix}No fix in el{ctx.rhel_ver}_{installed_minor}. "
                    f"Fix in other streams: {best_ref}.")
    else:
        compare_fixes = unique_fixed

    all_pass = True
    any_compared = False
    any_fail_fix = None
    for fix_v in compare_fixes:
        try:
            cmp_inst, cmp_fix = _normalize_epoch(found_v, fix_v)
            any_compared = True
            if compare_versions(cmp_inst, cmp_fix) < 0:
                all_pass = False
                if any_fail_fix is None:
                    any_fail_fix = fix_v
        except Exception:
            pass

    if all_pass and compare_fixes and any_compared:
        _decide(compare_fixes[0], 'rpm_fixed_pass', False)
        note = f"{sn + '; ' if sn else ''}Installed {found_v} >= fix {compare_fixes[0]}."
        return ("✅ FALSE POSITIVE", compare_fixes[0], note)
    if any_fail_fix:
        _decide(any_fail_fix, 'rpm_fixed_fail', True)
        note = f"{sn + '; ' if sn else ''}Installed {found_v} < fix {any_fail_fix}."
        return ("❌ POSITIVE", any_fail_fix, note)
    fix_ref = compare_fixes[0] if compare_fixes else "?"
    _decide(compare_fixes[0] if compare_fixes else None, 'rpm_fixed_fail', bool(compare_fixes))
    note = f"{sn + '; ' if sn else ''}Installed {found_v} < fix {fix_ref}."
    return ("❌ POSITIVE", compare_fixes[0] if compare_fixes else "N/A", note)


def _decide_rpm(comp, found_v, data, ctx, maps, rhel_ver, rpm_rhel, dec, srpm=''):
    """RPM decision ladder (rungs 5, 5s, 8, 9).  Returns (verdict, fix, note)."""
    pid_name, rel_parent, rhel_base_pids, pid_purl, vex_ns_map, pid_cpe, pid_ident = maps
    names = _resolve_comp(comp, ctx) | _src_alias_names(data, comp, found_v, srpm)
    installed_minor = _detect_rhel_minor(found_v)

    vulns = data.get('vulnerabilities', [])
    if not vulns:
        dec['kind'] = 'no_vulns'
        return ("❌ POSITIVE", "N/A", "No vulnerability entries in VEX.")

    for vuln in vulns:
        ps = vuln.get('product_status', {})
        cands = _rpm_candidates(vuln, ctx, maps, names, found_v, comp=comp)
        # Lineage guard (§6b): a versioned clear-side candidate (fixed / KNA
        # NEVRA) from another build lineage must not be version-compared —
        # a RHEL erratum can neither clear nor fail an OCP rhaos build.
        # Version-less product-level pids and affected-side statuses stay:
        # they assert state, they don't enter a version comparison.
        cands = [(s, p, v) for s, p, v in cands
                 if not v or s in ('known_affected', 'under_investigation')
                 or _stream_comparable(found_v, v)]

        # rung 5 — status priority KNA > fixed > KA > UI ---------------------
        # A not-affected claim cannot clear an installed build with a PENDING
        # applicable fix: kna rows often describe the FIXED build (its .src /
        # sibling arches) or the product line at large, not the older NEVRA
        # actually installed.  Stream applicability follows §6b: minor-stream
        # installs consider only their own stream's fixes; GA installs must be
        # ≥ every stream fix.  A component with NO fixed candidates (a truly
        # not-affected subpackage like bind-utils) is untouched by this guard.
        def _fix_pending():
            for _status, _pid, _ver in cands:
                if _status != 'fixed' or not _ver:
                    continue
                fix_minor = _detect_rhel_minor(_ver)
                if installed_minor and fix_minor and fix_minor != installed_minor:
                    continue
                try:
                    _inst, _fix = _normalize_epoch(found_v, _ver)
                    if compare_versions(_inst, _fix) < 0:
                        return True
                except Exception:
                    continue
            return False

        if not _fix_pending():
            # KNA (stream-aware: a KNA from another minor stream doesn't apply)
            for status, pid, ver in cands:
                if status != 'known_not_affected':
                    continue
                if installed_minor and ver:
                    kna_minor = _detect_rhel_minor(ver)
                    if kna_minor and kna_minor != installed_minor:
                        continue
                dec.update(kind='rpm_kna', status='known_not_affected', pids=[pid])
                sn = _sbom_note(comp, found_v, ctx) if rpm_rhel else ''
                prefix = f"{sn}; " if sn else ''
                return ("✅ FALSE POSITIVE", "N/A",
                        f"{prefix}{ctx.display_name}: known_not_affected.")

        # fixed → §6 version compare (RHEL base-repo fixes preferred as ref)
        scoped_fixed = [(ver, pid.split(':')[0] in rhel_base_pids, pid)
                        for status, pid, ver in cands if status == 'fixed' and ver]
        if scoped_fixed:
            scoped_fixed.sort(key=lambda t: not t[1])   # base repos first
            seen, unique_fixed, fix_pid_by_ver = set(), [], {}
            for v, _b, pid in scoped_fixed:
                if v not in seen:
                    seen.add(v)
                    unique_fixed.append(v)
                    fix_pid_by_ver[v] = pid
            return _compare_fixed(found_v, unique_fixed, comp, ctx, rpm_rhel, dec, fix_pid_by_ver)

        # known_affected → POSITIVE (permanent no-fix / fix-elsewhere / no-fix)
        ka_pids = [pid for status, pid, _ver in cands if status == 'known_affected']
        if ka_pids:
            pid = ka_pids[0]
            dec.update(kind='rpm_ka', status='known_affected', pids=[pid])
            no_fix_pids = {p for r in vuln.get('remediations', [])
                           if r.get('category') == 'no_fix_planned'
                           for p in r.get('product_ids', [])}
            other_products = set()
            for fpid in ps.get('fixed', []):
                if (_is_any_rhel_ver_product(fpid, rhel_ver)
                        and not _pid_in_scope(fpid, ctx, pid_name, rhel_base_pids,
                                              vex_ns_map, pid_cpe=pid_cpe)):
                    fpkg, _ = _pkg_from_pid(fpid, pid_ident)
                    if fpkg and fpkg in names:
                        other_products.add(_pid_label(fpid, pid_name, rel_parent))
            sn = _sbom_note(comp, found_v, ctx) if rpm_rhel else ''
            prefix = f"{sn}; " if sn else ''
            if pid in no_fix_pids:
                note = f"{prefix}known_affected. no_fix_planned."
            elif other_products:
                note = f"{prefix}known_affected. Fix only in: {', '.join(sorted(other_products))}."
            else:
                note = f"{prefix}known_affected. No fix available."
            return ("❌ POSITIVE", "N/A", note)

        # under_investigation → POSITIVE
        ui_pids = [pid for status, pid, _ver in cands if status == 'under_investigation']
        if ui_pids:
            dec.update(kind='rpm_ui', status='under_investigation', pids=[ui_pids[0]])
            return ("❌ POSITIVE", "N/A", f"under_investigation for {ctx.display_name}.")

        # rung 8 — related products (out-of-scope RHEL-N / version-neutral) ---
        # Packages Red Hat tracks per RHEL major anywhere in this file.
        rhel_tracked = set()
        for status in ('fixed', 'known_affected', 'known_not_affected'):
            for pid in ps.get(status, []):
                if 'enterprise_linux' in pid.lower() or re.search(r'[.+]el\d', pid):
                    nm, _ = _pkg_from_pid(pid, pid_ident)
                    if nm:
                        rhel_tracked.add(nm)
        other_vuln, other_safe = set(), set()
        other_vuln_pids, other_safe_pids = [], []
        for status in ('fixed', 'known_affected', 'known_not_affected'):
            for pid in ps.get(status, []):
                if ((_is_any_rhel_ver_product(pid, rhel_ver) or _is_version_neutral_product(pid))
                        and not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids,
                                              vex_ns_map, pid_cpe=pid_cpe)):
                    if not _module_stream_compatible(pid, found_v):
                        continue
                    pkg_name, _pkg_ver = _pkg_from_pid(pid, pid_ident)
                    if (pkg_name and _is_version_neutral_product(pid)
                            and pkg_name in rhel_tracked):
                        # Red Hat enumerates this package per RHEL major (it
                        # appears under RHEL base products elsewhere in this
                        # file), so our major's absence is informative — §5g.
                        # A standalone product's bundled copy then says nothing:
                        # JBoss EWS 3 and Directory Server 8 ship their own pcre,
                        # unrelated to RHEL 9's, and flagging on the shared NAME
                        # marks a current package vulnerable forever over a 2015
                        # CVE in a product we do not run.  openshift-clients is
                        # the opposite case — RHEL never ships it, so the
                        # version-neutral OCP PID is the only statement there is.
                        continue
                    if pkg_name in names:
                        label = _pid_label(pid, pid_name, rel_parent)
                        if status in ('known_affected', 'fixed'):
                            other_vuln.add(label)
                            other_vuln_pids.append(pid)
                        else:
                            other_safe.add(label)
                            other_safe_pids.append(pid)

        # clear-only related products carry no claim about OUR product — fall
        # through to rung 9 (not listed); only affected-elsewhere stays decisive
        # (conservative POSITIVE, never a borrowed clear).
        if other_vuln:
            dec.update(kind='rpm_related_vuln', pids=other_vuln_pids)
            return ("❌ POSITIVE", "N/A",
                    f"'{comp}' affected in related products ({', '.join(sorted(other_vuln))}).")

        # rung 9 — not listed: Red Hat enumerates affected products per CVE;
        # a component absent from that enumeration is not affected (§5g — the
        # errata assumption covers only listed products, never silence).
        img_status, img_lbl, img_pids = _image_level_open_verdict(data, ctx, maps)
        if img_status:
            dec.update(kind='rpm_img_open', status=img_status, pids=img_pids)
            what = ('under_investigation — Red Hat has not assessed this yet'
                    if img_status == 'under_investigation' else 'known_affected')
            return ("❌ POSITIVE", "N/A",
                    f"{what}. This image: {', '.join(sorted(set(img_lbl))[:2])}.")
        ui_lbl, ui_pids = _scoped_under_investigation(data, ctx, maps, comp, names)
        if ui_lbl:
            dec.update(kind='rpm_ui_scope', status='under_investigation', pids=ui_pids)
            return ("❌ POSITIVE", "N/A",
                    f"under_investigation in {', '.join(sorted(set(ui_lbl))[:3])} — "
                    f"Red Hat has not assessed this yet.")
        dec['kind'] = 'rpm_not_listed'
        return ("✅ FALSE POSITIVE", "N/A", f"'{comp}' not listed as affected in VEX.")

    dec['kind'] = 'no_vulns'
    return ("❌ POSITIVE", "N/A", "No vulnerability entries in VEX.")


# ══════════════════════════════════════════════════════════════════════════════
# §8 3/4/7  Non-RPM path — image identity, same-image builds, errata, family
# ══════════════════════════════════════════════════════════════════════════════

def _build_stamp(s: Optional[str]) -> Optional[int]:
    """Normalize a build identifier to a comparable YYYYMMDDHHMM integer.

    Red Hat image builds carry either a Brew timestamp (`v4.15.0-202404030309…`,
    release label `202509030106.p2…`) or an epoch-seconds tag (`1781813947`).
    """
    if not s:
        return None
    m = re.search(r'\b(20\d{10})\b', s)                 # YYYYMMDDHHMM
    if m:
        return int(m.group(1))
    m = re.search(r'\b(1[5-9]\d{8})\b', s)              # epoch seconds (2017+)
    if m:
        import time
        return int(time.strftime('%Y%m%d%H%M', time.gmtime(int(m.group(1)))))
    return None


def _purl_build_stamp(pid: str, pid_purl: dict) -> Optional[int]:
    """Build stamp of a VEX image PID, read from its purl's `tag=` qparam."""
    leaf = pid.split(':', 1)[1] if ':' in pid else pid
    purl = pid_purl.get(pid) or pid_purl.get(leaf)
    if not purl:
        for k, v in pid_purl.items():
            if leaf.endswith(k) or k.endswith(leaf):
                purl = v
                break
    if not purl:
        return None
    m = re.search(r'[?&]tag=([^&]+)', purl)
    return _build_stamp(m.group(1)) if m else None


def _image_identity_lookup(ctx, data, maps, dec):
    """Image-identity evidence for OCP/operator workloads (rungs 3a/3b, 4, 7).

    One walk collects candidate image PIDs {status, pid, rhel_quality, sha_spec}
    that match the workload image by OCI purl / image-path / generic component or
    by our exact digest.  Ranking: our-digest (spec 2) overrides everything;
    then RHEL-variant quality (exact -rhelN = 2, version-neutral = 1, other = 0);
    at equal quality, affected wins.  When nothing matches but the family was
    assessed, applies the errata policy (§5g) against RHOSE-4.x fixed streams.

    Returns (verdict, pid, extra, family_assessed) or None; populates *dec* with
    the decisive PID so severity/state read from it.  Verdicts are the internal
    tokens POSITIVE / FALSE_POSITIVE / POSITIVE_OTHER_RHEL / NOT_LISTED.
    """
    pid_name, rel_parent, rhel_base_pids, pid_purl, vex_ns_map, pid_cpe, pid_ident = maps

    _label_name = f"{ctx.image_ns}/{ctx.image_name}" if (ctx.image_ns and ctx.image_name) else None
    _candidates, _image_sha = _build_image_purl(ctx.image_ref, _label_name)
    _purl_matched_pids = _purl_matched_leaf_pids(pid_purl, _candidates)
    _own_sha_set = _own_shas(ctx)

    # PIDs carrying our exact digest → their parsed leaf is a purl-equivalent match
    if _own_sha_set:
        for vuln in data.get('vulnerabilities', []):
            ps = vuln.get('product_status', {})
            for status in ('known_not_affected', 'known_affected', 'fixed', 'under_investigation'):
                for pid in ps.get(status, []):
                    if _extract_sha256(pid) in _own_sha_set:
                        _leaf, _ = _pkg_from_pid(pid, pid_ident)
                        if _leaf:
                            _purl_matched_pids.add(_leaf)

    if ctx.workload_type == "ocp":
        comp = ctx.ocp_component or (
            _normalize_vex_image_core(ctx.image_name) if ctx.image_name else None)
        if not comp:
            return None
        _comp_norm = _normalize_ocp_component(comp)

        def _matches(pid_pkg):
            if pid_pkg in _purl_matched_pids:
                return True
            if '/' in pid_pkg:
                return _normalize_vex_image_core(pid_pkg) == comp
            return _normalize_ocp_component(pid_pkg) == _comp_norm
    elif ctx.workload_type == "operator":
        if not ctx.image_name:
            return None

        def _matches(pid_pkg):
            if pid_pkg in _purl_matched_pids:
                return True
            return pid_pkg.split('/')[-1] == ctx.image_name
    else:
        return None

    def _is_generic(pid_pkg):
        return pid_purl.get(pid_pkg, '').startswith('pkg:generic/')

    def _spec(pid):
        sha = _extract_sha256(pid)
        return 2 if (sha and sha in _own_sha_set) else 1

    matches = []          # (status, pid, rhel_quality, flag_label, specificity)
    family_assessed = False

    for vuln in data.get('vulnerabilities', []):
        ps = vuln.get('product_status', {})
        flags = vuln.get('flags', [])
        flag_map = {}
        for flag in flags:
            for pid in flag.get('product_ids', []):
                flag_map[pid] = flag.get('label', '')

        def _consider(status, pid, flag_lbl):
            nonlocal family_assessed
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map, pid_cpe=pid_cpe):
                return
            pid_pkg, _ = _pkg_from_pid(pid, pid_ident)
            if not pid_pkg:
                return
            has_path = '/' in pid_pkg
            is_generic = not has_path and _is_generic(pid_pkg)
            if not has_path and not is_generic:
                return
            if has_path:
                family_assessed = True
            if not _matches(pid_pkg):
                return
            if is_generic:
                family_assessed = True
            pid_rhel = _extract_rhel_from_vex_image(pid_pkg)
            rhel_q = 2 if pid_rhel == ctx.rhel_ver else (1 if pid_rhel is None else 0)
            matches.append((status, pid, rhel_q, flag_lbl, _spec(pid)))

        for status in ('known_not_affected', 'known_affected', 'fixed', 'under_investigation'):
            for pid in ps.get(status, []):
                _consider(status, pid, flag_map.get(pid, ''))
        for flag in flags:
            if flag.get('label') not in _NOT_AFFECTED_FLAGS:
                continue
            for pid in flag.get('product_ids', []):
                if any(p == pid and s == 'known_not_affected' for s, p, _, _, _ in matches):
                    continue
                _consider('known_not_affected', pid, flag.get('label', ''))

    # our-digest assessments override generic ones
    if any(m[4] == 2 for m in matches):
        matches = [m for m in matches if m[4] == 2]

    if not matches:
        # rung 7 — errata policy (no family match for this OCP version)
        if not family_assessed and ctx.workload_type == "ocp" and ctx.ocp_ver:
            cur_parts = [int(x) for x in ctx.ocp_ver.split('.') if x.isdigit()]
            fixed_ocp_vers = set()
            for vuln in data.get('vulnerabilities', []):
                for pid in vuln.get('product_status', {}).get('fixed', []):
                    m = re.search(r'RHOSE[.-](\d+\.\d+)', pid)
                    if m:
                        fixed_ocp_vers.add(m.group(1))
            if fixed_ocp_vers:
                newest_fix = max(fixed_ocp_vers, key=lambda v: [int(x) for x in v.split('.')])
                fix_parts = [int(x) for x in newest_fix.split('.')]
                if cur_parts == fix_parts:
                    return ('FALSE_POSITIVE', '', f'errata_fixed:{newest_fix}', False)
                if fix_parts < cur_parts:
                    return ('FALSE_POSITIVE', '', f'errata_not_previous:{newest_fix}', False)
        return ('NOT_LISTED', '', '', True) if family_assessed else None

    best_quality = max(m[2] for m in matches)
    if best_quality == 0:
        aff = [(s, p, fl) for s, p, q, fl, _sp in matches
               if s in ('known_affected', 'under_investigation')]
        if aff:
            return ('POSITIVE_OTHER_RHEL', aff[0][1], aff[0][2], family_assessed)
        return ('NOT_LISTED', '', '', True) if family_assessed else None

    candidates = [(s, p, fl) for s, p, q, fl, _sp in matches if q >= max(best_quality, 1)]
    if not candidates:
        return ('NOT_LISTED', '', '', True) if family_assessed else None

    has_affected = any(s in ('known_affected', 'under_investigation') for s, _, _ in candidates)
    if has_affected:
        pid_match = next(p for s, p, _ in candidates if s in ('known_affected', 'under_investigation'))
        status = next(s for s, _, _ in candidates if s in ('known_affected', 'under_investigation'))

        # errata override: a generic (no RHOSE-stream) known_affected PID catches
        # all OCP 4.x; a version NEWER than the newest fixed stream is not a
        # "previous version" (§5g) → FALSE POSITIVE.
        if ctx.workload_type == "ocp" and ctx.ocp_ver:
            affected_has_stream = any(
                re.search(r'RHOSE[.-]\d+\.\d+', p)
                for s, p, q, fl, _sp in matches
                if s in ('known_affected', 'under_investigation'))
            if not affected_has_stream:
                cur_parts = [int(x) for x in ctx.ocp_ver.split('.') if x.isdigit()]
                cur_minor = '.'.join(str(x) for x in cur_parts[:2])
                fixed_ocp_vers = set()
                for vuln in data.get('vulnerabilities', []):
                    for fpid in vuln.get('product_status', {}).get('fixed', []):
                        fm = re.search(r'RHOSE[.-](\d+\.\d+)', fpid)
                        if fm:
                            fixed_ocp_vers.add(fm.group(1))
                if fixed_ocp_vers:
                    if cur_minor in fixed_ocp_vers:
                        return ('FALSE_POSITIVE', pid_match, f'errata_fixed:{cur_minor}', family_assessed)
                    newest_fix = max(fixed_ocp_vers, key=lambda v: [int(x) for x in v.split('.')])
                    if [int(x) for x in newest_fix.split('.')] < cur_parts:
                        return ('FALSE_POSITIVE', pid_match, f'errata_not_previous:{newest_fix}', family_assessed)

        return ('POSITIVE', pid_match, status, family_assessed)

    has_kna = any(s == 'known_not_affected' for s, _, _ in candidates)
    if has_kna:
        pid_match = next(p for s, p, _ in candidates if s == 'known_not_affected')
        flag_lbl = next((fl for s, _, fl in candidates if s == 'known_not_affected' and fl), '')
        return ('FALSE_POSITIVE', pid_match, flag_lbl, family_assessed)

    # fixed only: a fixed PID carrying a digest that is NOT ours names another
    # build.  Digests cannot be ordered — compare Brew build stamps (purl `tag=`
    # vs this build's version-release): ours ≥ newest fix → rebuild carries the
    # fix (not a "previous version", §5g) → FALSE POSITIVE; ours older →
    # POSITIVE.  A generic (digest-less) fixed PID clears the stream outright;
    # with no comparable stamps, the stream's fix predates a modern rebuild in
    # the corpus norm — treated as cleared.
    fixed_generic = [p for s, p, _ in candidates if s == 'fixed' and not _extract_sha256(p)]
    if fixed_generic:
        return ('FALSE_POSITIVE', fixed_generic[0], '', family_assessed)
    fixed_other = [p for s, p, _ in candidates if s == 'fixed']
    if fixed_other:
        ours = _build_stamp(ctx.image_build)
        stamps = [t for t in (_purl_build_stamp(p, pid_purl) for p in fixed_other) if t]
        if ours and stamps:
            if ours >= max(stamps):
                return ('FALSE_POSITIVE', fixed_other[0], '', family_assessed)
            return ('POSITIVE', fixed_other[0], 'fixed', family_assessed)
        return ('FALSE_POSITIVE', fixed_other[0], '', family_assessed)

    return ('NOT_LISTED', '', '', True) if family_assessed else None


def _audit_nonrpm_image_sha(comp, found_v, data, ctx, maps, our_shas, row, dec):
    """Image-level VEX PIDs carrying an @sha256 digest (rung 4).  Returns
    (verdict, fix, note) or None."""
    pid_name, rel_parent, rhel_base_pids, pid_purl, vex_ns_map, pid_cpe, pid_ident = maps
    comp_base = re.sub(r'[@:][^/]*$', '', comp)
    img_not_affected = False
    img_fixed_label = None
    img_fixed_pid = None
    img_fixed_ver = str(row.get('FIXED_VERSION', '')) if 'FIXED_VERSION' in row.index else None

    for vuln in data.get('vulnerabilities', []):
        ps = vuln.get('product_status', {})
        for status in ('known_not_affected', 'fixed', 'known_affected', 'under_investigation'):
            for pid in ps.get(status, []):
                if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map, pid_cpe=pid_cpe):
                    continue
                pid_sha = _extract_sha256(pid)
                if not pid_sha:
                    continue
                pid_image = re.sub(r'@sha256:[a-f0-9]+.*$', '',
                                   pid.split(':', 1)[-1] if ':' in pid else pid)
                if pid_image != comp_base:
                    continue
                lbl = _pid_label(pid, pid_name, rel_parent)
                if status == 'known_not_affected':
                    if pid_sha in our_shas:
                        dec.update(kind='img_sha_kna', status='known_not_affected', pids=[pid])
                        return ("✅ FALSE POSITIVE", "N/A", f"Image build not affected ({lbl}).")
                    img_not_affected = True
                elif status == 'fixed':
                    if pid_sha in our_shas:
                        dec.update(kind='img_sha_fixed', status='fixed', pids=[pid])
                        return ("✅ FALSE POSITIVE", "N/A", f"Image build is the fixed version ({lbl}).")
                    img_fixed_label = lbl
                    img_fixed_pid = pid
                elif status == 'known_affected':
                    if pid_sha in our_shas:
                        dec.update(kind='img_sha_ka', status='known_affected', pids=[pid],
                                   fix_set=bool(img_fixed_ver))
                        fix_note = f"; fix: {img_fixed_ver}" if img_fixed_ver else ""
                        return ("❌ POSITIVE", img_fixed_ver or "N/A", f"Image build affected ({lbl}){fix_note}.")
                elif status == 'under_investigation':
                    if pid_sha in our_shas:
                        dec.update(kind='img_sha_ui', status='under_investigation', pids=[pid])
                        return ("❌ POSITIVE", "N/A", f"under_investigation for {ctx.display_name}.")

    if img_fixed_label and not img_not_affected:
        dec.update(kind='img_sha_fixed_older', pids=[img_fixed_pid] if img_fixed_pid else [],
                   fix_set=bool(img_fixed_ver))
        fix_note = f" Fix: {img_fixed_ver}." if img_fixed_ver else ""
        return ("❌ POSITIVE", img_fixed_ver or "N/A",
                f"Fixed build exists ({img_fixed_label}); installed {found_v} is older.{fix_note}")
    return None


def _pid_is_our_image(pid: str, ctx: WorkloadContext) -> bool:
    """Does this PID's component name OUR image (not a sibling in the product)?

    Identity, in the order VEX-MODEL §8b ranks it: our exact digest, then the
    image path/name, then the derived OCP component.  Being in scope is NOT
    enough — an OCP workload has every OpenShift image in scope, and treating a
    statement about `ose-hypershift-rhel9` as one about `ose-cli` is the same
    over-broad match that produced bugs 8 and 12.
    """
    comp = pid.split(':', 1)[-1] if ':' in pid else pid
    sha = _extract_sha256(pid)
    if sha:
        return sha in _own_shas(ctx)
    if '/' not in comp and '@' not in comp:
        return False                       # a package name, not an image path
    base = re.sub(r'@sha256:.*$', '', comp).split('/')[-1].lower()
    ours = {x.lower() for x in (ctx.image_name or '', ctx.ocp_component or '') if x}
    if base in ours:
        return True
    core = _normalize_vex_image_core(comp)
    return bool(core) and (core.lower() in ours
                           or (ctx.ocp_component
                               and _normalize_ocp_component(core)
                               == _normalize_ocp_component(ctx.ocp_component)))


def _image_level_open_verdict(data, ctx, maps):
    """(status, labels, pids) when a statement about OUR IMAGE leaves it open.

    Identity hierarchy (§8b): our digest, then our image, then our product, then
    the component.  A statement about the image outranks the component level, so
    reaching rung 9 ("this package is not named") while Red Hat says the IMAGE is
    known_affected — or is still under_investigation — reports a confirmed clear
    the vendor never gave.

    CVE-2026-39833 names `red_hat_web_terminal:web-terminal/web-terminal-tooling-rhel9`
    as known_affected and no libgcc PID at all; libgcc inside that image was
    being called a FALSE POSITIVE.  CVE-2026-45287 is the same shape with
    under_investigation.
    """
    pid_name, rel_parent, rhel_base_pids, _pp, vex_ns_map, pid_cpe, _ident = maps
    for status in ('known_affected', 'under_investigation'):
        labels, pids = [], []
        for vuln in data.get('vulnerabilities', []):
            for pid in vuln.get('product_status', {}).get(status, []):
                if not _pid_is_our_image(pid, ctx):
                    continue
                if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                     pid_cpe=pid_cpe):
                    continue
                labels.append(_pid_label(pid, pid_name, rel_parent))
                pids.append(pid)
        if labels:
            return status, labels, pids
    return None, [], []


def _scoped_under_investigation(data, ctx, maps, comp=None, names=()):
    """(labels, pids) of `under_investigation` statements about US.

    §5a: under_investigation means Red Hat has NOT decided yet, and the rule is
    to treat it as vulnerable.  A rung-9 "not listed as affected" reached while
    such a statement covers our image is a false suppression — it reports a
    confirmed clear where the vendor explicitly said "unknown".  Seen on
    CVE-2026-45287, whose only statement about us is
    `red_hat_web_terminal:web-terminal/web-terminal-tooling-rhel9` under
    investigation, while every component of that image was called a FALSE
    POSITIVE.

    Restricted to OUR image or OUR component on purpose: an in-scope UI naming a
    sibling image (`ose-hypershift-rhel9`) or an unrelated package (`buildah`)
    says nothing about this finding.
    """
    pid_name, rel_parent, rhel_base_pids, _pp, vex_ns_map, pid_cpe, pid_ident = maps
    want = {n for n in (set(names) | ({comp} if comp else set())) if n}
    labels, pids = [], []
    for vuln in data.get('vulnerabilities', []):
        for pid in vuln.get('product_status', {}).get('under_investigation', []):
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                continue
            pkg, _ = _pkg_from_pid(pid, pid_ident)
            if not (_pid_is_our_image(pid, ctx) or (pkg and pkg in want)):
                continue
            labels.append(_pid_label(pid, pid_name, rel_parent))
            pids.append(pid)
    return labels, pids


def _scoped_affected(data, ctx, maps):
    """(labels, pids) of in-scope known_affected products for this workload.

    Non-empty means Red Hat lists THIS product as affected by the CVE — the
    precondition of the errata sentence (§5g): "unless explicitly stated as not
    affected, all previous versions of packages in any minor update stream of a
    product listed here should be assumed vulnerable".
    """
    pid_name, rel_parent, rhel_base_pids, _pid_purl, vex_ns_map, pid_cpe, _ident = maps
    labels, pids = [], []
    for vuln in data.get('vulnerabilities', []):
        for pid in vuln.get('product_status', {}).get('known_affected', []):
            if _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map, pid_cpe=pid_cpe):
                labels.append(_pid_label(pid, pid_name, rel_parent))
                pids.append(pid)
    return labels, pids


def _clears_under(data, ctx, maps, affected_pids) -> list:
    """In-scope clears belonging to the SAME parent product(s) listed as affected.

    Answers "did Red Hat assess *us* for this CVE", and the parent restriction is
    load-bearing.  `_pid_in_scope` deliberately admits any product carrying the
    workload's RHEL major (§8a, so Fast Datapath and friends are not missed), so
    a plain in-scope sweep for an OCP 4.12 / RHEL8 image also returns
    8Base-RHACM-2.9, 8Base-multicluster-engine-2.4, 8Base-RHACS-4.5,
    8Base-GitOps-1.14 — 490 of 521 clears on CVE-2024-45337 come from products
    that are not ours.  RHACM clearing its own images says nothing about whether
    ose-cli was assessed, so only clears under a parent Red Hat also listed as
    affected count as evidence that the enumeration covered us.
    """
    parents = {p.split(':')[0] for p in affected_pids}
    if not parents:
        return []
    pid_name, _rel, rhel_base_pids, _pp, vex_ns_map, pid_cpe, _ident = maps
    out = []
    for vuln in data.get('vulnerabilities', []):
        ps = vuln.get('product_status', {})
        for status in ('known_not_affected', 'fixed'):
            for pid in ps.get(status, []):
                if pid.split(':')[0] not in parents:
                    continue
                if _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                    out.append(pid)
    return out


def _errata_assumed_vulnerable(labels, pids, dec, what: str):
    """Apply the errata assumption to a non-RPM component of a listed product.

    Only called when Red Hat lists this product as affected AND cleared nothing
    in our scope — i.e. they never assessed us for this CVE, so the errata
    sentence governs: "unless explicitly stated as not affected, all previous
    versions of packages in any minor update stream of a product listed here
    should be assumed vulnerable".  A sibling image of a listed product is not
    enumerated (CVE-2026-42507 names web-terminal-exec-rhel9 while
    web-terminal-tooling-rhel9 appears nowhere), so silence is not a
    not-affected claim.  When in-scope clears DO exist the caller keeps the
    FALSE POSITIVE — the enumeration covered us and absence is meaningful.

    The rpm path never reaches here: Red Hat enumerates rpms exhaustively (every
    binary subpackage, per arch, §9.1), so an absent rpm is already meaningful.
    """
    dec.update(kind='ft_errata_assumed', status='known_affected', pids=pids)
    return ("❌ POSITIVE", "N/A",
            f"{what} not explicitly cleared; Red Hat lists "
            f"{', '.join(sorted(set(labels))[:3])} as affected and cleared nothing in "
            f"this scope — per Red Hat's errata policy, assumed vulnerable.")


def _audit_nonrpm_fallthrough(comp, ctx, maps, affected, fixed, not_affected,
                              investigating, data, dec):
    """Non-RPM fallthrough — product-family clear (rung 6), else not-listed.

    Strict-VEX: every statement naming this component or this image was consumed
    by the earlier rungs, so any in-scope known_affected PID reaching this point
    describes a *different* component (e.g. RHEL base RPMs vendoring the same
    library).  Red Hat enumerates the affected products per CVE; a product/
    component absent from that enumeration is not listed as affected → FALSE
    POSITIVE (the errata-policy assumption covers only products *listed* on the
    CVE).  Only an in-scope under_investigation statement keeps a row POSITIVE
    here — that is a real VEX statement that the scope is being assessed.
    """
    pid_name, rel_parent, rhel_base_pids, pid_purl, vex_ns_map, pid_cpe, pid_ident = maps

    if ctx.workload_type != "ubi":
        scoped_affected, aff_pids = _scoped_affected(data, ctx, maps)
        scoped_investigating, scoped_clear = [], []
        inv_pids, clear_pids = [], []
        for vuln in data.get('vulnerabilities', []):
            ps = vuln.get('product_status', {})
            for pid in ps.get('under_investigation', []):
                if _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map, pid_cpe=pid_cpe):
                    scoped_investigating.append(_pid_label(pid, pid_name, rel_parent))
                    inv_pids.append(pid)
            for status in ('known_not_affected', 'fixed'):
                for pid in ps.get(status, []):
                    if _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map, pid_cpe=pid_cpe):
                        scoped_clear.append(_pid_label(pid, pid_name, rel_parent))
                        clear_pids.append(pid)
        if scoped_investigating and not scoped_affected:
            dec.update(kind='ft_ui', status='under_investigation', pids=inv_pids)
            return ("❌ POSITIVE", "N/A",
                    f"under_investigation in {', '.join(sorted(set(scoped_investigating))[:3])}.")
        if scoped_clear and not scoped_affected and not scoped_investigating:
            dec.update(kind='ft_clear', pids=clear_pids)
            return ("✅ FALSE POSITIVE", "N/A",
                    f"No affected entry in {', '.join(sorted(set(scoped_clear))[:3])} "
                    f"(known_not_affected/fixed only).")
        if scoped_affected:
            if _clears_under(data, ctx, maps, aff_pids):
                # Red Hat cleared builds in our scope for this CVE, so the
                # enumeration did cover us and our absence from known_affected
                # is meaningful (§5g).
                dec['kind'] = 'ft_novex_scoped'
                return ("✅ FALSE POSITIVE", "N/A",
                        f"Not listed as affected; known_affected in "
                        f"{', '.join(sorted(set(scoped_affected))[:3])} names other "
                        f"components only.")
            return _errata_assumed_vulnerable(scoped_affected, aff_pids, dec, comp)

    if ctx.workload_type == "operator" and (affected or investigating or fixed):
        dec['kind'] = 'ft_operator_novex'
        return ("✅ FALSE POSITIVE", "N/A",
                f"Not listed as affected; no VEX statement for {ctx.display_name}.")

    if investigating:
        dec.update(kind='ft_investigating_ui', status='under_investigation')
        return ("❌ POSITIVE", "N/A", f"under_investigation in {', '.join(investigating[:3])}.")

    if not_affected and not affected and not fixed:
        dec['kind'] = 'ft_not_affected'
        return ("✅ FALSE POSITIVE", "N/A", f"known_not_affected in {', '.join(not_affected[:3])}.")

    if affected and not_affected and ctx.rhel_ver:
        rhel_tag = f"RHEL {ctx.rhel_ver}"
        rhel_tag_long = f"Red Hat Enterprise Linux {ctx.rhel_ver}"
        workload_rhel_clear = any(rhel_tag in na or rhel_tag_long in na for na in not_affected)
        workload_rhel_affected = any(rhel_tag in af or rhel_tag_long in af for af in affected)
        if workload_rhel_clear and not workload_rhel_affected:
            dec['kind'] = 'ft_rhel_clear'
            return ("✅ FALSE POSITIVE", "N/A",
                    f"RHEL {ctx.rhel_ver} not affected. Only affects: {', '.join(affected[:2])}.")

    parts = []
    if affected:     parts.append(f"affected: {', '.join(affected[:3])}")
    if fixed:        parts.append(f"fixed: {', '.join(fixed[:3])}")
    if not_affected: parts.append(f"not affected: {', '.join(not_affected[:3])}")
    dec['kind'] = 'ft_other'
    return ("✅ FALSE POSITIVE", "N/A",
            f"Not listed as affected; no VEX entry for {ctx.display_name}. "
            f"Other products: {'; '.join(parts)}.")


def _decide_nonrpm(comp, found_v, data, ctx, maps, row, dec):
    """Non-RPM decision ladder (rungs 3, 4, 6, 7, 8, 9).  Returns (verdict, fix, note)."""
    pid_name, rel_parent, rhel_base_pids, pid_purl, vex_ns_map, pid_cpe, pid_ident = maps
    affected, fixed, not_affected, investigating = _summarise_vex_products(data, pid_name, rel_parent)

    if not affected and not fixed and not not_affected and not investigating:
        dec['kind'] = 'nonrpm_not_listed'
        return ("✅ FALSE POSITIVE", "N/A",
                "Not listed as affected; VEX names no products for this CVE.")

    if ctx.workload_type != "ubi":
        # rungs 3/4/7 — image identity
        if ctx.workload_type in ("ocp", "operator"):
            img_result = _image_identity_lookup(ctx, data, maps, dec)
            if img_result is not None:
                verdict, pid_match, extra, _fam = img_result
                _pids = [pid_match] if pid_match else []
                if pid_match:
                    lbl = _pid_label(pid_match, pid_name, rel_parent)
                    pid_pkg = pid_match.split(':', 1)[1] if ':' in pid_match else pid_match
                    img_lbl = f"{lbl} — {pid_pkg}" if pid_pkg not in lbl else lbl
                else:
                    img_lbl = ctx.display_name

                if verdict == 'FALSE_POSITIVE':
                    if extra and extra.startswith('errata_'):
                        _tag, fixed_in_ver = extra.split(':', 1)
                        if _tag == 'errata_fixed':
                            dec.update(kind='errata_fixed', status='fixed', pids=_pids)
                            return ("✅ FALSE POSITIVE", "N/A", f"Fixed in OCP {fixed_in_ver}.")
                        # errata_not_previous: no statement names our stream —
                        # §5g inference only, never published
                        dec.update(kind='errata_newer', pids=_pids)
                        return ("✅ FALSE POSITIVE", "N/A",
                                f"Build newer than newest fixed stream (OCP {fixed_in_ver}).")
                    flag_desc = f" ({extra.replace('_', ' ')})" if extra else ""
                    sha = _extract_sha256(pid_match) if pid_match else None
                    parent = pid_match.split(':', 1)[0].strip() if pid_match else ''
                    if sha and sha not in _own_shas(ctx):
                        # Digest-pinned statement about ANOTHER build of this
                        # image.  Red Hat assesses vendored Go at the component
                        # image rather than the module purl (2 golang purls in
                        # the whole corpus), so this IS the vendor's verdict for
                        # those subcomponents — but it describes one build's
                        # content, so it only travels to ours when:
                        #   (a) the claim is about content ("vulnerable code not
                        #       present"/"component not present"), not a shipped
                        #       fix, which is build-ordered; and
                        #   (b) our build is at least as new as the assessed one
                        #       — measured, 33 of 44 such statements describe a
                        #       NEWER build, where the vulnerable dependency may
                        #       since have been bumped out, so the claim must
                        #       never travel backwards.
                        # Tried and rejected: gating the transfer on a content
                        # claim plus "our build is newer" (tests B3).  Build
                        # stamps order TIME, not CONTENT — a newer build of ours
                        # can have added the very dependency the older assessed
                        # build lacked, so a "code not present" claim still does
                        # not travel.  The sound way to publish Red Hat's Go
                        # verdict is to triage the build Red Hat assessed (a
                        # published registry.redhat.io digest), not to move a
                        # build-exact claim between builds.
                        dec['unstated'] = True
                    elif not sha and re.search(r'\d+\.\d+$', parent):
                        # versionless image PID under a minor-versioned product
                        # (e.g. "Web Terminal 1.11") — claim is scoped to that
                        # product release, our build's membership is unproven
                        dec['unstated'] = True
                    dec.update(kind='img_fp_kna', pids=_pids)
                    return ("✅ FALSE POSITIVE", "N/A", f"known_not_affected{flag_desc}. {img_lbl}.")
                if verdict == 'POSITIVE':
                    vex_status = extra if extra in (
                        'known_affected', 'under_investigation', 'fixed') else 'known_affected'
                    if vex_status == 'under_investigation':
                        dec.update(kind='img_pos_ui', status='under_investigation', pids=_pids)
                        return ("❌ POSITIVE", "N/A", f"under_investigation. {img_lbl}.")
                    if vex_status == 'fixed':
                        dec.update(kind='img_pos_fixed_older', status='known_affected',
                                   pids=_pids, fix_set=False)
                        return ("❌ POSITIVE", "N/A",
                                f"Fixed build exists ({img_lbl}); this build predates it.")
                    dec.update(kind='img_pos', status='known_affected', pids=_pids)
                    return ("❌ POSITIVE", "N/A", f"{vex_status}. {img_lbl}.")
                if verdict == 'POSITIVE_OTHER_RHEL':
                    dec.update(kind='img_pos', status='known_affected', pids=_pids)
                    return ("❌ POSITIVE", "N/A", f"known_affected for different RHEL ({img_lbl}).")
                if verdict == 'NOT_LISTED':
                    if not (ctx.sbom_src_map and ctx.sbom_src_map.get(comp)):
                        comp_ref = ctx.ocp_component or ctx.display_name
                        # Our image is not named — but if Red Hat lists this
                        # product as affected, the errata sentence covers it:
                        # sibling images of a listed product are not enumerated,
                        # so silence is not a not-affected claim.
                        _st, _lbl, _pids = _image_level_open_verdict(data, ctx, maps)
                        if _st:
                            dec.update(kind='img_open', status=_st, pids=_pids)
                            _what = ('under_investigation — Red Hat has not assessed this yet'
                                     if _st == 'under_investigation' else 'known_affected')
                            return ("❌ POSITIVE", "N/A",
                                    f"{_what}. This image: "
                                    f"{', '.join(sorted(set(_lbl))[:2])}.")
                        _ui_lbl, _ui_pids = _scoped_under_investigation(
                            data, ctx, maps, comp, _resolve_comp(comp, ctx))
                        if _ui_lbl:
                            dec.update(kind='img_ui_scope', status='under_investigation',
                                       pids=_ui_pids)
                            return ("❌ POSITIVE", "N/A",
                                    f"under_investigation in "
                                    f"{', '.join(sorted(set(_ui_lbl))[:3])} — Red Hat has not "
                                    f"assessed this yet.")
                        _aff_lbl, _aff_pids = _scoped_affected(data, ctx, maps)
                        if _aff_lbl and not _clears_under(data, ctx, maps, _aff_pids):
                            return _errata_assumed_vulnerable(_aff_lbl, _aff_pids, dec, comp_ref)
                        dec.update(kind='img_not_listed', pids=[])
                        return ("✅ FALSE POSITIVE", "N/A",
                                f"{comp_ref} not listed as affected.")
                    # The component has a vendoring-rpm alias (go binary
                    # shipped inside an rpm): Red Hat may track this CVE on
                    # the rpm rather than the image — fall through to the
                    # component rungs, which match the alias via
                    # _resolve_comp (rhel9:buildah for golang.org/x/net).

        # not-affected flags scoped to our component / digest
        #
        # "a '/' means an image" (§3a rule 5) is a rule about VEX component
        # names.  Applied to a SCANNER component it swallows every Go module
        # path — github.com/sigstore/fulcio, golang.org/x/net — and the image
        # branch below skips the package-name check, so ANY in-scope
        # not-affected flag would clear ANY Go module no matter which component
        # the flag actually names.  The scanner's SOURCE is what distinguishes
        # them: an image-identity pseudo-component is SOURCE=OS with a path in
        # its name (§7b), a Go/npm/maven module never is.
        # NOTE: "a '/' means an image" (§3a rule 5) is a rule about VEX component
        # names; applied to a SCANNER component it also captures Go module paths
        # (github.com/sigstore/fulcio).  Restricting it with the row's SOURCE was
        # tried and REVERTED: it changes Go clears in the permissive direction
        # (a RHEL-base not-affected flag naming the vendoring rpm would start
        # clearing the module) and no observed defect required it — the two rows
        # that prompted it turned out to be the vendoring-rpm bridge working
        # correctly.  Left as-is deliberately; needs evidence before changing.
        is_image_comp = '/' in comp
        for vuln in data.get('vulnerabilities', []):
            for flag in vuln.get('flags', []):
                if flag.get('label') not in _NOT_AFFECTED_FLAGS:
                    continue
                for pid in flag.get('product_ids', []):
                    if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map, pid_cpe=pid_cpe):
                        continue
                    pid_sha = _extract_sha256(pid)
                    if pid_sha:
                        if pid_sha not in _own_shas(ctx):
                            continue
                    elif is_image_comp and _is_rhel_base_product(pid, ctx.rhel_ver, rhel_base_pids):
                        continue
                    else:
                        flag_pkg, _ = _pkg_from_pid(pid, pid_ident)
                        if flag_pkg and flag_pkg not in _resolve_comp(comp, ctx):
                            continue
                    lbl = _pid_label(pid, pid_name, rel_parent)
                    dec.update(kind='nonrpm_flag', status='known_not_affected', pids=[pid])
                    return ("✅ FALSE POSITIVE", "N/A",
                            f"Not affected in {ctx.display_name} ({lbl}): "
                            f"{flag.get('label', 'flag').replace('_', ' ')}.")

        our_shas = _own_shas(ctx)
        is_image_component = '/' in comp

        if is_image_component:
            result = _audit_nonrpm_image_sha(comp, found_v, data, ctx, maps, our_shas, row, dec)
            if result is not None:
                return result

        # generic product_status scan (non-SHA PIDs matched by name)
        for vuln in data.get('vulnerabilities', []):
            ps = vuln.get('product_status', {})
            for status in ('known_not_affected', 'known_affected', 'fixed', 'under_investigation'):
                for pid in ps.get(status, []):
                    if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map, pid_cpe=pid_cpe):
                        continue
                    pid_sha = _extract_sha256(pid)
                    if pid_sha:
                        if pid_sha not in our_shas:
                            continue
                    else:
                        pid_pkg, _ = _pkg_from_pid(pid, pid_ident)
                        if pid_pkg and pid_pkg not in _resolve_comp(comp, ctx):
                            continue
                    lbl = _pid_label(pid, pid_name, rel_parent)
                    if status == 'under_investigation':
                        dec.update(kind='nonrpm_ps_ui', status='under_investigation', pids=[pid])
                        return ("❌ POSITIVE", "N/A", f"under_investigation for {ctx.display_name}.")
                    if status == "known_not_affected":
                        dec.update(kind='nonrpm_ps_kna', status='known_not_affected', pids=[pid])
                        return ("✅ FALSE POSITIVE", "N/A", f"known_not_affected ({lbl}).")
                    if status == "fixed":
                        dec.update(kind='nonrpm_ps_fixed', status='fixed', pids=[pid])
                        return ("❌ POSITIVE", "N/A", f"Fix exists ({lbl}); installed version not verified.")
                    dec.update(kind='nonrpm_ps_ka', status='known_affected', pids=[pid])
                    return ("❌ POSITIVE", "N/A", f"known_affected ({lbl}).")

    return _audit_nonrpm_fallthrough(comp, ctx, maps, affected, fixed,
                                     not_affected, investigating, data, dec)


# ══════════════════════════════════════════════════════════════════════════════
# The pipeline entry points
# ══════════════════════════════════════════════════════════════════════════════

@functools.lru_cache(maxsize=int(os.environ.get('VEX_CACHE_SIZE', '512')))
def _load_vex(cve_id: str) -> Optional[dict]:
    """Load + cache a Red Hat VEX JSON by CVE ID (shared across audit calls)."""
    vex_path = os.path.join(VEX_DIR, f"{cve_id}.json")
    if not os.path.exists(vex_path):
        return None
    try:
        with open(vex_path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except Exception as exc:
        import logging
        logging.warning("Corrupt VEX file %s: %s — deleting to allow re-download", vex_path, exc)
        try:
            os.unlink(vex_path)
        except OSError:
            pass
        return None


def _evaluate(row, ctx, data, maps):
    """Rungs 1-2 then the RPM/non-RPM split.  Returns (verdict, fix, note, dec)."""
    pid_name, rel_parent, rhel_base_pids, pid_purl, vex_ns_map, pid_cpe, pid_ident = maps
    comp    = row['COMPONENT']
    found_v = str(row['VERSION'])
    dec = {'kind': '', 'pids': [], 'status': '', 'fix_set': False}

    # rung 1 — vendor catch-all (document-level, pre-scope)
    if _is_catchall_not_affected(data):
        dec['kind'] = 'catchall'
        return ("✅ FALSE POSITIVE", "N/A", "No supported Red Hat product affected.", dec)

    # rung 2 — our-digest override (pre-scope, pre-name; whole build)
    img_shas = _own_shas(ctx)
    if img_shas:
        sha_hits = {}
        for vuln in data.get('vulnerabilities', []):
            ps_ = vuln.get('product_status', {})
            for status in ('known_affected', 'under_investigation', 'fixed', 'known_not_affected'):
                for pid in ps_.get(status, []):
                    if any(sh in pid for sh in img_shas):
                        sha_hits.setdefault(status, pid)
        if sha_hits:
            if 'known_affected' in sha_hits or 'under_investigation' in sha_hits:
                st = 'known_affected' if 'known_affected' in sha_hits else 'under_investigation'
            else:
                st = 'known_not_affected' if 'known_not_affected' in sha_hits else 'fixed'
            decisive = sha_hits[st]
            lbl = _pid_label(decisive, pid_name, rel_parent)
            if st in ('known_affected', 'under_investigation'):
                dec.update(kind='digest_' + ('ka' if st == 'known_affected' else 'ui'),
                           status=st, pids=[decisive])
                return ("❌ POSITIVE", "N/A", f"{st} — this image build ({lbl}).", dec)
            if st == 'fixed':
                dec.update(kind='digest_fixed', status='fixed', pids=[decisive])
                return ("✅ FALSE POSITIVE", "N/A", f"This image build is the fixed build ({lbl}).", dec)
            dec.update(kind='digest_kna', status='known_not_affected', pids=[decisive])
            return ("✅ FALSE POSITIVE", "N/A", f"known_not_affected — this image build ({lbl}).", dec)

    # RPM vs non-RPM split (§8b): '/' component or no .elN marker ⇒ non-RPM
    if '/' in comp:
        rpm_rhel = None
    else:
        rpm_rhel = _detect_rhel_ver(found_v)
        comp_source = str(row.get('SOURCE', '')) if 'SOURCE' in row.index else ''
        if not rpm_rhel and comp_source == 'OS':
            rpm_rhel = ctx.rhel_ver

    rhel_ver = rpm_rhel or ctx.rhel_ver
    if rpm_rhel and rpm_rhel != ctx.rhel_ver:
        # per-row RHEL: the RPM's own .elN marker is authoritative (mixed images)
        ctx = WorkloadContext(**{f.name: getattr(ctx, f.name)
                                 for f in ctx.__dataclass_fields__.values()})
        ctx.rhel_ver = rpm_rhel

    if not rpm_rhel:
        verdict, fix, note = _decide_nonrpm(comp, found_v, data, ctx, maps, row, dec)
        # SBOM verification (VEX-MODEL §7f): confirm the scanner-reported
        # component against the image's own SPDX inventory.  Image-identity
        # pseudo-components (SOURCE=OS, '/' in name) are image refs, not
        # packages — never in the SBOM.
        comp_source = str(row.get('SOURCE', '')) if 'SOURCE' in row.index else ''
        if not ('/' in comp and comp_source == 'OS'):
            sn = _sbom_note(comp, found_v, ctx)
            if sn:
                note = f"{note} {sn}." if note.endswith('.') else f"{note}; {sn}."
    else:
        _srpm = str(row.get('SRPM', '') or '') if 'SRPM' in row.index else ''
        if _srpm.lower() in ('nan', 'none'):
            _srpm = ''
        verdict, fix, note = _decide_rpm(comp, found_v, data, ctx, maps, rhel_ver,
                                         rpm_rhel, dec, _srpm)
    return verdict, fix, note, dec


def audit_row_detailed(row, ctx: WorkloadContext):
    """Triage one CVE finding against the Red Hat VEX corpus.

    Returns pd.Series([verdict, fix_version, justification, severity, state,
    stated]).  Severity, state and fix are all read from the single decisive
    match.  `stated` is True only when a VEX statement names the scanned
    product/image/component — verdicts derived from silence carry False and
    must never be published as OpenVEX claims.
    """
    import pandas as pd
    cve = str(row['CVE']).strip().upper()
    data = _load_vex(cve)
    if data is None:
        return pd.Series(["❌ POSITIVE", "N/A", "VEX file missing.", "Unknown", "Unknown", False])

    maps = _build_pid_name(data)
    pid_name, rel_parent, rhel_base_pids, pid_purl, vex_ns_map, pid_cpe, pid_ident = maps
    pid_severity = _build_pid_severity_map(data)

    verdict, fix, note, dec = _evaluate(row, ctx, data, maps)

    severity = _severity_from_decisive(
        data, dec, ctx, row['COMPONENT'], row, pid_severity, pid_name,
        rhel_base_pids, vex_ns_map, pid_cpe, pid_purl)
    state = _state_from_decisive(
        verdict, dec, data, ctx, pid_name, rhel_base_pids, vex_ns_map, pid_cpe)
    stated = (dec.get('kind', '') not in _UNSTATED_KINDS
              and not dec.get('unstated', False))
    return pd.Series([verdict, fix, note, severity, state, stated])


# ══════════════════════════════════════════════════════════════════════════════
# VEX_PRODUCT column helper (used by report builders; shares the scope predicate)
# ══════════════════════════════════════════════════════════════════════════════

def _get_vex_product(data: dict, comp: str, ctx) -> str:
    """Short product label(s) for the VEX entry matching *comp* in *ctx*."""
    (pid_name, rel_parent, rhel_base_pids, _pid_purl, vex_ns_map, _pid_cpe,
     pid_ident) = _build_pid_name(data)
    labels: set = set()
    any_in_scope = False
    for vuln in data.get('vulnerabilities', []):
        ps    = vuln.get('product_status', {})
        flags = vuln.get('flags', [])
        all_pids: set = set()
        for s in ('known_affected', 'fixed', 'known_not_affected', 'under_investigation'):
            all_pids.update(ps.get(s, []))
        for flag in flags:
            if flag.get('label') in _NOT_AFFECTED_FLAGS:
                all_pids.update(flag.get('product_ids', []))
        for pid in all_pids:
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map, pid_cpe=_pid_cpe):
                continue
            any_in_scope = True
            pkg_name, _ = _pkg_from_pid(pid, pid_ident)
            if pkg_name in _resolve_comp(comp, ctx) and pid in rel_parent:
                labels.add(rel_parent[pid])
    if labels:
        return ', '.join(sorted(labels))
    if any_in_scope and ctx.display_name:
        return ctx.display_name
    return ''


def _vex_product_for_row(row, ctx) -> str:
    """df.apply wrapper for _get_vex_product."""
    cve  = str(row.get('CVE', '')).strip().upper()
    comp = str(row.get('COMPONENT', ''))
    data = _load_vex(cve)
    if not data:
        return ''
    try:
        return _get_vex_product(data, comp, ctx)
    except Exception:
        return ''
