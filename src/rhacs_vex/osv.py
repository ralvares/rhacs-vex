"""Advisory-ID → CVE resolution through OSV, so ecosystem IDs reach the VEX.

Scanners report Go, Python and npm findings under the ID the ecosystem assigned:
`GHSA-mv93-w799-cj2w`, `GO-2026-5932`.  Red Hat publishes VEX per CVE, so those
rows hit rung 10 ("no VEX file to be absent from") and come out POSITIVE with an
Unknown severity and an Unknown state, regardless of what Red Hat actually says.

OSV carries the alias graph.  Where the advisory has a CVE, the row can be
looked up like any other and the engine decides it properly — measured on three
real RHOAI workbench rows, gitpython went POSITIVE/Unknown → FALSE POSITIVE
(Red Hat lists it not affected), and tornado and jupyterlab stayed POSITIVE but
gained their real severity and Red Hat state ("Affected", "Fix deferred").

Coverage is partial and that is a property of the data, not of this module.  Of
27 advisory IDs sampled from 180 RHACS scans, 7 carried a CVE alias; the rest
are Go advisories that pair a `GHSA-` with a `GO-` and nothing else.  Following
that pair is pointless — every `GO-` record checked aliases straight back to its
own `GHSA-` — so only the direct record is read.  Six of the seven resolved CVEs
had a Red Hat VEX document.

Unresolved IDs are left exactly as they were: rung 10 is the correct answer when
no CVE exists to look up.  Nothing here touches disk — the alias map is memoised
for the life of the process and re-read from OSV next run.
"""
from __future__ import annotations

import functools
import json
import os
from concurrent.futures import ThreadPoolExecutor

import requests

_API = 'https://api.osv.dev/v1/vulns/'
_WORKERS = int(os.environ.get('OSV_WORKERS', '8'))

# Memoised per process, never written to disk.  A scan carries a handful of
# advisory IDs (14 on the largest RHOAI workbench measured), so one lookup each
# per run costs a second and leaves nothing behind to go stale or to be mistaken
# for part of the VEX mirror.


def is_advisory_id(vuln_id: str) -> bool:
    """True for an ecosystem advisory ID — anything that is not a CVE."""
    v = str(vuln_id or '').strip()
    return bool(v) and not v.upper().startswith('CVE-')


def _canonical(vuln_id: str) -> str:
    """OSV's exact spelling, which the API matches literally.

    A GHSA is an upper-case prefix over a lower-case base32 suffix, and OSV
    404s on any other casing — `GHSA-mv93-w799-cj2w` serves, `GHSA-MV93-…` and
    `ghsa-mv93-…` do not.  RHACS reports the ID upper-cased throughout, so this
    is not a theoretical case.  Everything else (`GO-`, `PYSEC-`, `RUSTSEC-`)
    is upper.
    """
    v = str(vuln_id or '').strip()
    prefix, sep, rest = v.partition('-')
    if not sep:
        return v.upper()
    return (f'{prefix.upper()}-{rest.lower()}' if prefix.upper() == 'GHSA'
            else v.upper())


@functools.lru_cache(maxsize=4096)
def resolve(vuln_id: str):
    """The CVE this advisory aliases, or None.  Never raises, never blocks long.

    A network failure returns None and the caller keeps the original ID, where
    rung 10 still applies — the verdict is the one the tool gives today.
    """
    if not is_advisory_id(vuln_id):
        return None
    try:
        res = requests.get(_API + _canonical(vuln_id), timeout=15)
        if res.status_code != 200:          # 404 = OSV does not know the ID
            return None
        # OSV serves records with raw newlines inside `details`, which strict
        # JSON rejects; the payload is otherwise well formed.
        doc = json.loads(res.text, strict=False)
    except Exception:
        return None
    cves = sorted(a for a in (doc.get('aliases') or []) + (doc.get('upstream') or [])
                  if str(a).upper().startswith('CVE-'))
    return cves[0] if cves else None


def resolve_many(vuln_ids, workers: int = 0) -> dict:
    """{advisory_id: CVE} for the IDs that resolve; unresolved ones are absent."""
    ids = [i for i in dict.fromkeys(vuln_ids) if is_advisory_id(i)]
    if not ids:
        return {}
    with ThreadPoolExecutor(max_workers=max(1, workers or _WORKERS)) as ex:
        found = list(ex.map(resolve, ids))
    return {i: c for i, c in zip(ids, found) if c}
