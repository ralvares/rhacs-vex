"""Package URLs: just enough of the spec to read Red Hat's, syft's, grype's and trivy's."""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote, unquote


@dataclass(frozen=True)
class Purl:
    type: str = ''
    namespace: str = ''
    name: str = ''
    version: str = ''
    qualifiers: dict = field(default_factory=dict, compare=False, hash=False)

    def q(self, key: str, default: str = '') -> str:
        return self.qualifiers.get(key, default)

    def __str__(self) -> str:
        return build(self.type, self.namespace, self.name, self.version, self.qualifiers)


def parse(s: str) -> Purl:
    """pkg:type/namespace/name@version?qualifiers#subpath — every field decoded."""
    if not s or not s.startswith('pkg:'):
        return Purl()
    body = s[4:].split('#', 1)[0]
    body, _, query = body.partition('?')
    quals = {}
    for kv in query.split('&'):
        if '=' in kv:
            k, v = kv.split('=', 1)
            quals[k.lower()] = unquote(v)
    path, _, version = body.partition('@')
    segs = [unquote(x) for x in path.strip('/').split('/')]
    typ = segs[0].lower()
    name = segs[-1] if len(segs) > 1 else ''
    return Purl(typ, '/'.join(segs[1:-1]), name, unquote(version), quals)


def build(typ: str, namespace: str, name: str, version: str = '', qualifiers: dict | None = None) -> str:
    ns = '/'.join(quote(x, safe='') for x in namespace.split('/') if x)
    out = f'pkg:{typ}/' + (f'{ns}/' if ns else '') + quote(name, safe='')
    if version:
        out += '@' + quote(version, safe=':+~')
    q = {k: v for k, v in (qualifiers or {}).items() if v}
    if q:
        out += '?' + '&'.join(f'{k}={quote(str(v), safe="/:")}' for k, v in sorted(q.items()))
    return out
