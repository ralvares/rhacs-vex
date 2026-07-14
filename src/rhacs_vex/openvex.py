"""openvex.py — OpenVEX statement emitter for triage verdicts.

Turns the triage result DataFrame (AUDIT_RESULT / VEX_STATE / JUSTIFICATION
columns, as produced by triage._audit_silent / the report CSVs) into OpenVEX
statements consumable by grype and trivy.

The purl rules are empirical, proven against both scanners
(docs/OPENVEX-SPIKE-RESULTS.md):

  * product  @id  = pkg:oci/<basename>@sha256:<pull-digest> — bare, NO
    qualifiers.  A `repository_url=` qualifier breaks grype; a missing digest
    would leak the verdict across OCP versions that share the image name.
  * subcomponents = bare purls, ALL qualifiers stripped (`distro=`, `arch=`,
    `upstream=`, `epoch=` are each scanner-specific and fail cross-tool).
  * golang versions diverge between scanners (grype `stdlib@1.20.12` vs trivy
    `stdlib@v1.20.12`) → both variants are emitted for every golang component.

Scope is suppression-only: statement-backed FALSE POSITIVE rows (VEX_STATED)
become `not_affected` or `fixed` statements; POSITIVE rows and FALSE
POSITIVEs derived from the component's absence in the VEX are never emitted
(VEX-MODEL: state only what the VEX itself states).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import pandas as pd

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

# The five OpenVEX justification labels — byte-identical to the Red Hat CSAF
# flag labels (engine._NOT_AFFECTED_FLAGS), so no translation table is needed.
JUSTIFICATIONS = {
    'component_not_present',
    'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist',
}

# VEX_STATE (humanized, from engine) → OpenVEX status.  Only these two states
# co-occur with ✅ FALSE POSITIVE; everything else stays out of the document.
_STATE_TO_STATUS = {
    'Not affected': 'not_affected',
    'Fixed':        'fixed',
    'Fix available': 'fixed',   # FP + fix available ⇒ installed ≥ fix (backport)
}


# --- image / component purl minting -----------------------------------------

def split_image_ref(image_ref: str):
    """(registry, namespace-path, basename, digest) from a pinned image ref."""
    ref = str(image_ref).strip()
    m = re.match(r'^(?P<path>[^@]+)@(?P<digest>sha256:[a-f0-9]{64})$', ref)
    if not m:
        raise ValueError(f"image ref must be digest-pinned: {ref!r}")
    path, digest = m.group('path'), m.group('digest')
    parts = path.split('/')
    registry = parts[0] if ('.' in parts[0] or ':' in parts[0]) else ''
    rest = parts[1:] if registry else parts
    name = rest[-1].split(':')[0]
    namespace = '/'.join(rest[:-1])
    return registry, namespace, name, digest


def product_id(image_ref: str) -> str:
    """OpenVEX product @id for an image — bare OCI purl, digest-pinned."""
    _, _, name, digest = split_image_ref(image_ref)
    return f"pkg:oci/{name}@{digest}"


def repository_path(image_ref: str) -> str:
    """registry/namespace/name — the hub location path and index qualifier."""
    registry, namespace, name, _ = split_image_ref(image_ref)
    return '/'.join(p for p in (registry, namespace, name) if p)


def _pep503(name: str) -> str:
    return re.sub(r'[-_.]+', '-', name).lower()


def subcomponent_ids(component: str, version: str, source: str) -> list:
    """Bare subcomponent purl variant(s) for one finding row.

    Qualifier-free by rule; golang gets both the v-prefixed and bare version
    because grype and trivy disagree (spike finding #2).
    """
    comp, ver, src = str(component).strip(), str(version).strip(), str(source).strip().upper()
    if not comp or not ver:
        return []
    if src == 'GO':
        ver = re.sub(r'^go', '', ver)           # grype reports stdlib as go1.20.12
        bare = ver[1:] if ver.startswith('v') else ver
        return [f"pkg:golang/{comp}@{bare}", f"pkg:golang/{comp}@v{bare}"]
    if src == 'OS':
        ver = re.sub(r'^\d+:', '', ver)         # epoch is a qualifier in purl, not version
        return [f"pkg:rpm/redhat/{comp}@{ver}"]
    if src == 'PYTHON':
        return [f"pkg:pypi/{_pep503(comp)}@{ver}"]
    if src == 'NODEJS':
        return [f"pkg:npm/{comp}@{ver}"]
    if src == 'JAVA':
        return [f"pkg:maven/{comp}@{ver}"] if '/' in comp else []
    return []


# --- justification recovery --------------------------------------------------

def _justification_from_text(justification: str) -> Optional[str]:
    """Recover the raw CSAF flag from the engine's humanized justification.

    The engine renders flags as `known_not_affected (<label with spaces>)`;
    the reverse map is exact membership in the OpenVEX enum — anything else
    returns None and the statement carries an impact_statement instead.
    """
    for m in re.finditer(r'\(([a-z ]+)\)', str(justification)):
        candidate = m.group(1).strip().replace(' ', '_')
        if candidate in JUSTIFICATIONS:
            return candidate
    return None


# --- statement / document assembly -------------------------------------------

def statements_from_df(df: pd.DataFrame, image_ref: str) -> list:
    """OpenVEX statements for the FALSE POSITIVE rows of one image's triage df.

    Grouped by (CVE, status): one statement per verdict, subcomponents merged
    across the components that share it.
    """
    if df is None or df.empty:
        return []
    prod = product_id(image_ref)

    # (CVE, srpm) pairs where sibling binary rpms of one source diverge — some
    # cleared, some still open (e.g. bind-utils not_affected while bind-libs
    # awaits its fix).  trivy normalizes rpm findings to the SOURCE package
    # when matching VEX, so ANY statement about one sibling suppresses them
    # all — including the genuinely affected ones.  Emitting nothing for the
    # divergent group is the only safe option: the cleared siblings stay
    # visible (a false positive shown), the affected ones stay visible (a real
    # vulnerability NOT hidden).
    def _row_srpm(row):
        srpm = str(row.get('SRPM', '') or '').strip()
        if srpm and srpm.lower() != 'nan' and \
                str(row.get('SOURCE', '')).strip().upper() == 'OS':
            return srpm
        return ''

    divergent = set()
    for _, row in df.iterrows():
        if 'FALSE POSITIVE' in str(row.get('AUDIT_RESULT', '')):
            continue
        cve = str(row.get('CVE', '')).strip().upper()
        srpm = _row_srpm(row)
        if srpm:
            divergent.add((cve, srpm))
        # rpm identities an open verdict occupies: the rpm row itself, and the
        # vendoring rpm of a non-OS component (go binary inside an rpm) — a
        # statement must never re-claim these via an extension.
        if str(row.get('SOURCE', '')).strip().upper() == 'OS':
            divergent.add((cve, f"{row.get('COMPONENT', '')}@{row.get('VERSION', '')}"))
        owner = str(row.get('OWNER_RPM', '') or '').strip()
        if owner and owner.lower() != 'nan':
            divergent.add((cve, owner))

    fp = df[df['AUDIT_RESULT'].astype(str).str.contains('FALSE POSITIVE', na=False)]
    # Publish only statement-backed verdicts: a FALSE POSITIVE derived from
    # the component's ABSENCE in the VEX (engine VEX_STATED=False) is a triage
    # display verdict, not a Red Hat claim — emitting not_affected for it
    # would suppress the finding on the vendor's behalf.  (Bool survives CSV
    # round-trips as the string "True"/"False".)
    if 'VEX_STATED' in fp.columns:
        fp = fp[fp['VEX_STATED'].astype(str).str.strip().str.lower().isin(('true', '1'))]
    groups: dict = {}
    for _, row in fp.iterrows():
        status = _STATE_TO_STATUS.get(str(row.get('VEX_STATE', '')).strip())
        if not status:
            continue
        srpm = _row_srpm(row)
        if srpm and (str(row.get('CVE', '')).strip().upper(), srpm) in divergent:
            continue
        subs = subcomponent_ids(row.get('COMPONENT', ''), row.get('VERSION', ''),
                                row.get('SOURCE', ''))
        if not subs:
            continue
        # Red Hat assesses rpms per SOURCE package: extend the statement to the
        # source-rpm name so a sibling binary subpackage flagged only by the
        # other scanner (e.g. trivy's net-snmp vs grype's net-snmp-libs) is
        # covered by the same verdict.  Safe here: divergent groups were
        # dropped above, so every sibling of this source shares the verdict.
        if srpm:
            subs += subcomponent_ids(srpm, row.get('VERSION', ''), 'OS')
        # Go binary vendored by an rpm: trivy reports the CVE against the rpm
        # (Red Hat advisory data), not the module purl — extend the verdict to
        # the owning rpm so both discovery views suppress.  Blocked when any
        # open verdict for this CVE occupies that rpm identity (divergent).
        owner = str(row.get('OWNER_RPM', '') or '').strip()
        if owner and owner.lower() != 'nan' and '@' in owner and \
                str(row.get('SOURCE', '')).strip().upper() != 'OS':
            cve_key = str(row.get('CVE', '')).strip().upper()
            if (cve_key, owner) not in divergent:
                oname, over = owner.split('@', 1)
                subs += subcomponent_ids(oname, over, 'OS')
        key = (str(row['CVE']).strip().upper(), status)
        g = groups.setdefault(key, {'subs': set(), 'just': None, 'impacts': set()})
        g['subs'].update(subs)
        if status == 'not_affected' and not g['just']:
            g['just'] = _justification_from_text(row.get('JUSTIFICATION', ''))
        if status == 'not_affected':
            text = str(row.get('JUSTIFICATION', '')).strip()
            if text and text.lower() != 'nan':
                g['impacts'].add(text)

    statements = []
    for (cve, status), g in sorted(groups.items()):
        products = [{
            '@id': prod,
            'subcomponents': [{'@id': s} for s in sorted(g['subs'])],
        }]
        # rpm subcomponents are also listed as products: trivy's BOM walk does
        # not reach the image root for base-layer packages, so the OCI product
        # alone never matches them.  Safe for rpm only — a Red Hat NEVRA is a
        # build identity (self-scoping); golang/python purls must stay scoped
        # under the image product or the verdict would leak across products.
        products += [{'@id': s} for s in sorted(g['subs'])
                     if s.startswith('pkg:rpm/')]
        stmt = {
            'vulnerability': {'name': cve},
            'products': products,
            'status': status,
        }
        if status == 'not_affected':
            if g['just']:
                stmt['justification'] = g['just']
            else:
                # spec: not_affected MUST carry justification or impact_statement
                stmt['impact_statement'] = ' | '.join(sorted(g['impacts'])) or \
                    'Not listed as affected in Red Hat CSAF-VEX for this product.'
        statements.append(stmt)
    return statements


def build_document(image_ref: str, statements: list, *, author: str,
                   doc_version: int = 1, timestamp: Optional[str] = None) -> dict:
    """Wrap statements in an OpenVEX document envelope."""
    _, _, name, digest = split_image_ref(image_ref)
    ts = timestamp or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    return {
        '@context': OPENVEX_CONTEXT,
        '@id': f"https://openvex.dev/docs/{quote(author, safe='')}/{name}",
        'author': author,
        'timestamp': ts,
        'version': doc_version,
        'statements': statements,
    }
