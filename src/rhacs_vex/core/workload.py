"""The scanned workload: which image this is, which product it belongs to.

One place builds it — from the pull reference, the image labels, the scanner's
OS string and any extra digests — and everything else only reads it
(VEX-MODEL §7c/§7d).  Classification is structural plus the catalog-generated
namespace map in data/ns_vex_prefixes.json; there is no hardcoded product list.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field, replace
from typing import List, Optional

BASE_DIR = "data"
NS_MAP_PATH = os.path.join(BASE_DIR, "ns_vex_prefixes.json")


def _load_ns_map() -> dict:
    try:
        with open(NS_MAP_PATH) as fh:
            return json.load(fh)
    except Exception:
        return {}


NS_TO_VEX_PREFIXES = _load_ns_map()


@dataclass
class WorkloadContext:
    """The workload a VEX product must be scoped to.

    workload_type ∈ {"ubi", "ocp", "operator"}.  `cpe` is the image-label CPE,
    `ocp_component` the OCP manifest component ("etcd").  `sbom_src_map`
    (component → source/owning rpm) and `sbom_packages` (name → [versions]) are
    filled by callers with SBOM access.  `extra_digests` are further sha256
    identities of THIS build (per-arch manifest, repo digests): VEX PIDs carry
    per-arch digests while a pull ref usually carries the manifest-list one.
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
    image_build   : Optional[str]   = None   # version-release of THIS build
    extra_digests : List[str]       = field(default_factory=list)

    # ── derived identity ────────────────────────────────────────────────────
    def own_digests(self) -> set:
        """Every sha256 hex that identifies this exact build."""
        shas = set()
        m = re.search(r'@sha256:([a-f0-9]+)', self.image_ref or '', re.IGNORECASE)
        if m:
            shas.add(m.group(1).lower())
        for d in self.extra_digests or []:
            m = re.search(r'([a-f0-9]{64})', str(d).lower())
            if m:
                shas.add(m.group(1))
        return shas

    def scope_key(self) -> tuple:
        """Everything the product-scope predicate depends on."""
        return (self.workload_type, self.rhel_ver, self.ocp_ver, self.image_ns,
                self.image_name, self.ocp_component, self.cpe,
                tuple(self.extra_prefixes))

    def with_rhel(self, rhel_ver: str) -> "WorkloadContext":
        return replace(self, rhel_ver=rhel_ver)

    def image_component(self) -> Optional[str]:
        """The OCP component core this image ships, if it is an OCP image."""
        return self.ocp_component or (
            image_core(self.image_name) if self.image_name else None)

    def oci_candidates(self) -> list:
        """(repository_url, image_name) pairs for OCI-purl matching (§4a).

        The pull reference is authoritative; the `name` label repo is the
        secondary route (art-dev pull paths name no image at all).
        """
        out = []
        if self.image_ref:
            bare = re.sub(r'[@:][^/]*$', '', self.image_ref)
            parts = bare.split('/')
            if len(parts) >= 2:
                out.append((bare, parts[-1]))
        label = (f"{self.image_ns}/{self.image_name}"
                 if self.image_ns and self.image_name else None)
        if label:
            repo = f"registry.redhat.io/{label}"
            if all(c[0] != repo for c in out):
                out.append((repo, label.split('/')[-1]))
        return out


# ── image-name normalisation (§8 3b) ─────────────────────────────────────────

def image_core(img: str) -> str:
    """'openshift4/ose-etcd-rhel9' → 'etcd' · '…/ose-cluster-etcd-rhel8-operator' →
    'cluster-etcd-operator'."""
    if '/' in img:
        img = img.split('/', 1)[1]
    if img.startswith('ose-'):
        img = img[4:]
    img = re.sub(r'-rhel\d+', '', img)
    return re.sub(r'--+', '-', img).strip('-')


def image_rhel(img: str) -> Optional[str]:
    m = re.search(r'-rhel(\d+)', img)
    return m.group(1) if m else None


_GENERIC_ALIASES = {'rhcos': 'rhel-coreos'}


def ocp_component_key(name: str) -> str:
    """Normalise OCP manifest / VEX generic names: rhcos ↔ rhel-coreos.

    The numbered node images stay distinct: `rhel-coreos-8` and `rhel-coreos-10`
    are separate builds on another RHEL major (other podman, other kernel), so a
    statement about one says nothing about the other or about `rhel-coreos`.
    """
    name = name.lower()
    return _GENERIC_ALIASES.get(name, name)


def same_ocp_component(ours: str, theirs: str, rhel: str = '') -> bool:
    """Does a VEX image / generic name denote our OCP payload component?

    RHCOS is named three ways: `rhel-coreos` in the release manifest, `rhcos`
    in Red Hat's generic / oci purls, and `ose-rhel-coreos-<N>` for the image
    of one RHEL major.  The unnumbered default node image is `rhel-coreos-<N>`
    for its own RHEL major (9 on OCP 4.13+), never for another; a numbered
    one (`rhel-coreos-10` beside the RHEL 9 default) is only itself.
    """
    a, b = ocp_component_key(ours), ocp_component_key(theirs)
    return a == b or (a == 'rhel-coreos' and bool(rhel) and b == f'rhel-coreos-{rhel}')


# ── builders ─────────────────────────────────────────────────────────────────

def parse_image_ref(image_ref: str, os_hint: str = "") -> WorkloadContext:
    """WorkloadContext from a pull reference alone.

    *os_hint* is the scanner's OS string; it overrides the path guess because an
    OCP payload path (`openshift-release-dev/ocp-v4.0-art-dev`) encodes no RHEL
    major and the "8" default would silently win on a RHEL 9/10 image.
    """
    ctx = WorkloadContext(image_ref=image_ref)
    path = re.sub(r'^[^/]+/', '', image_ref)
    path = re.sub(r'[@:][^/]*$', '', path)
    parts = path.split('/', 1)
    ns = parts[0].lower() if parts else ""
    name = parts[1].lower() if len(parts) > 1 else ""
    ctx.image_ns, ctx.image_name = ns, name

    rv = (re.search(r'rhel(\d+)', name) or re.search(r'rhel(\d+)', ns)
          or re.search(r'^ubi(\d+)$', ns))
    ctx.rhel_ver = rv.group(1) if rv else "8"
    if os_hint:
        om = re.search(r'(?:rhel|coreos|redhat)[^0-9]{0,3}(\d+)', str(os_hint).lower())
        if om:
            ctx.rhel_ver = om.group(1)

    tag = re.search(r'v(4\.\d+)', image_ref)
    if tag:
        ctx.ocp_ver = tag.group(1)

    if re.match(r'^ubi\d+', ns) or name == "" or ns in ("ubi", "rhel"):
        ctx.workload_type = "ubi"
        ctx.display_name = f"UBI{ctx.rhel_ver}"
    elif (ns in ("openshift4", "openshift", "ocp4", "openshift-release-dev")
          or "ose-" in name or name.startswith("ocp-")):
        ctx.workload_type = "ocp"
        ctx.display_name = f"OpenShift {ctx.ocp_ver or '4.x'}"
    else:
        ctx.workload_type = "operator"
        host = re.match(r'^([^/]+)/', image_ref)
        host = host.group(1) if host else "registry.redhat.io"
        ctx.extra_prefixes += [f"{host}/{ns}/", f"{ns}/"]
        for key, prefixes in NS_TO_VEX_PREFIXES.items():
            if key == ns or key in ns:
                ctx.extra_prefixes += [p for p in prefixes if p not in ctx.extra_prefixes]
        ctx.display_name = f"{ns}/{name} (RHEL {ctx.rhel_ver})"
    return ctx


def parse_context_from_labels(labels: dict, image_ref: str = "",
                              os_hint: str = "") -> WorkloadContext:
    """WorkloadContext from image labels + pull ref (§7c/§7d).

    The `name` label wins for identity (art-dev pull paths name no image), the
    pull path's namespace prefixes are merged in (label and registry namespaces
    disagree on ~18% of published images), the CPE refines RHEL major and
    product version, and the scanner's OS string — read from inside the image —
    outranks every naming convention.
    """
    cpe = labels.get("cpe", "")
    name = labels.get("name", "")

    ref = f"registry.redhat.io/{name}" if "/" in name else (image_ref or "")
    ctx = parse_image_ref(ref) if ref else WorkloadContext()
    if image_ref:
        ctx.image_ref = image_ref
    if image_ref and ctx.workload_type == "operator":
        for p in parse_image_ref(image_ref).extra_prefixes:
            if p not in ctx.extra_prefixes:
                ctx.extra_prefixes.append(p)

    if cpe:
        ctx.cpe = cpe
        parts = re.sub(r'^cpe:[/\d.]*:*', '', cpe).strip(':').split(':')
        version_tok = parts[3] if len(parts) > 3 else ""
        edition = parts[5].lower() if len(parts) > 5 else ""
        rhel_m = re.search(r'el(\d+)', edition)
        if rhel_m:
            ctx.rhel_ver = rhel_m.group(1)
        if version_tok:
            ctx.display_name = f"{ctx.display_name.split('(')[0].strip()} {version_tok}"
            if ctx.workload_type == "ocp":
                ctx.ocp_ver = version_tok
        product = parts[2].lower() if len(parts) > 2 else ""
        if ctx.workload_type == "operator" and product == "openshift":
            ctx.workload_type = "ocp"
            ctx.display_name = f"OpenShift {version_tok or ctx.ocp_ver or '4.x'}"
            ctx.extra_prefixes = []
            if version_tok:
                ctx.ocp_ver = version_tok

    if ctx.workload_type == "ocp" and not ctx.ocp_ver:
        m = re.match(r'v?(4\.\d+)', str(labels.get("version", "")))
        if m:
            ctx.ocp_ver = m.group(1)
            ctx.display_name = f"OpenShift {ctx.ocp_ver}"

    if labels.get("version") and labels.get("release"):
        ctx.image_build = f"{labels['version']}-{labels['release']}"
    elif image_ref and not ctx.image_build:
        m = re.search(r':(v?[\w.][^@/]*)$', image_ref)
        if m:
            ctx.image_build = m.group(1)

    if ctx.workload_type == "ocp" and name and not ctx.ocp_component:
        ctx.ocp_component = image_core(name)

    if image_ref:
        m = re.search(r'rhel(\d+)', re.sub(r'[@:][^/]*$', '', image_ref).split('/')[-1])
        if m:
            ctx.rhel_ver = m.group(1)

    if os_hint:
        m = re.search(r'(?:rhel|redhat)[:\-]?(\d+)', str(os_hint).lower())
        if m:
            ctx.rhel_ver = m.group(1)
    return ctx


_OS_HINT_RE = re.compile(r'(?:rhel|coreos|redhat)[^0-9]{0,3}(\d+)')


def rhel_from_os(os_hint) -> Optional[str]:
    """RHEL major from a scanner OS string ('rhel:9', 'Red Hat Enterprise Linux 9',
    'coreos 4.16 (rhel 9)')."""
    m = _OS_HINT_RE.search(str(os_hint or '').lower())
    return m.group(1) if m else None


def context_for_image(image_ref: str, *, os_hint: Optional[str] = None,
                      labels: Optional[dict] = None,
                      digests: Optional[list] = None,
                      ocp_release: Optional[str] = None,
                      ocp_component: Optional[str] = None) -> WorkloadContext:
    """THE workload builder every scan path uses.

    labels come from the scanner's own artifact (syft SBOM, trivy report, RHACS
    metadata); `skopeo inspect` is the fallback when none is given.
    *ocp_release* pins the context to an OCP release payload (`--ocp 4.16.3`):
    every image in a payload is an OCP component of that release, whatever its
    labels say.
    """
    if labels is None:
        labels = _skopeo_labels(image_ref)
    ctx = (parse_context_from_labels(labels, image_ref) if labels
           else parse_image_ref(image_ref))
    rhel = rhel_from_os(os_hint)
    if rhel:
        ctx.rhel_ver = rhel
    if digests:
        ctx.extra_digests = list(digests)
    if ocp_release:
        apply_ocp_release(ctx, ocp_release, component=ocp_component, os_known=bool(rhel))
    return ctx


def apply_ocp_release(ctx: WorkloadContext, release: str,
                      component: Optional[str] = None,
                      os_known: bool = False) -> WorkloadContext:
    """Pin a context to an OCP release payload (`oc adm release info` triage).

    Every image of a payload is an OCP component of that release whatever its
    labels say; the manifest's component name is authoritative.  A payload
    image without an OS hint takes its RHEL major from `rhel-coreos-N`.
    """
    ctx.workload_type = "ocp"
    ctx.ocp_ver = '.'.join(str(release).split('.')[:2])
    ctx.display_name = f"OpenShift {release}"
    ctx.extra_prefixes = []
    if component:
        ctx.ocp_component = component
        m = re.search(r'rhel-(?:[^-]+-)?(\d+)$', component)
        if m and not os_known:
            ctx.rhel_ver = m.group(1)
    return ctx


def _skopeo_labels(image_ref: str) -> dict:
    """Image labels via `skopeo inspect`, {} on any failure (fallback only)."""
    for extra in (['--override-os', 'linux'],
                  ['--override-os', 'linux', '--override-arch', 'amd64']):
        try:
            out = subprocess.run(['skopeo', 'inspect', *extra, f'docker://{image_ref}'],
                                 capture_output=True, text=True, timeout=120)
            if out.returncode == 0:
                return json.loads(out.stdout).get('Labels') or {}
        except Exception:
            pass
    return {}
