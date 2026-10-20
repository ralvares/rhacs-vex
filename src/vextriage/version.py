"""Version order for the language ecosystems (Go, npm, PyPI, Maven …).

`compare(eco, a, b)` → -1 / 0 / 1, or None when a version cannot be read
(`UNKNOWN`, empty, a git ref): an unreadable version is never ordered, so it
can never be "past a fix".
"""
from __future__ import annotations

import re
from typing import Optional

from .rpm import vercmp

_SEMVER = re.compile(r'^v?(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$')


def _semver_key(v: str):
    m = _SEMVER.match(v.strip())
    if not m:
        return None
    nums = [int(x) for x in m.group(1).split('.')]
    nums += [0] * (3 - len(nums))
    pre = m.group(2)
    return nums, (pre.split('.') if pre else None)


def _pre_cmp(a, b) -> int:
    """Semver prerelease precedence; None (a release) sorts after any prerelease."""
    if a is None or b is None:
        return 0 if a is b else (1 if a is None else -1)
    for x, y in zip(a, b):
        if x == y:
            continue
        xd, yd = x.isdigit(), y.isdigit()
        if xd and yd:
            return 1 if int(x) > int(y) else -1
        if xd != yd:
            return -1 if xd else 1          # numeric identifiers sort below words
        return 1 if x > y else -1
    return (len(a) > len(b)) - (len(a) < len(b))


def semver_cmp(a: str, b: str) -> Optional[int]:
    ka, kb = _semver_key(a), _semver_key(b)
    if ka is None or kb is None:
        return None
    if ka[0] != kb[0]:
        return 1 if ka[0] > kb[0] else -1
    return _pre_cmp(ka[1], kb[1])


_MAVEN_Q = {'alpha': 0, 'a': 0, 'beta': 1, 'b': 1, 'milestone': 2, 'm': 2, 'rc': 3, 'cr': 3,
            'snapshot': 4, '': 5, 'final': 5, 'ga': 5, 'release': 5, 'sp': 6}


def _maven_items(v: str):
    items = []
    for tok in re.findall(r'\d+|[A-Za-z]+', v.lower()):
        items.append((0, int(tok), '') if tok.isdigit() else (1, _MAVEN_Q.get(tok, 7), tok))
    while items and items[-1] in ((0, 0, ''), (1, 5, items[-1][2])):
        items.pop()                         # 1.0.0 == 1 == 1-final
    return items


def maven_cmp(a: str, b: str) -> Optional[int]:
    if not re.match(r'^\d', a or '') or not re.match(r'^\d', b or ''):
        return None
    x, y = _maven_items(a), _maven_items(b)
    for i in range(max(len(x), len(y))):
        p = x[i] if i < len(x) else None
        q = y[i] if i < len(y) else None
        if p == q:
            continue
        if p is None or q is None:
            # a missing item is a release: numbers beat it, qualifiers rank against 5
            other, sign = (q, -1) if p is None else (p, 1)
            if other[0] == 0:
                if other[1]:
                    return sign
                continue                    # 1.0 == 1
            if other[1] == 5:
                continue                    # 1-final == 1
            return sign if other[1] > 5 else -sign
        if p[0] != q[0]:                    # a number beats a qualifier
            return 1 if p[0] == 0 else -1
        if p[1] != q[1]:
            return 1 if p[1] > q[1] else -1
        if p[2] != q[2]:
            return 1 if p[2] > q[2] else -1
    return 0


def pep440_cmp(a: str, b: str) -> Optional[int]:
    try:
        from packaging.version import InvalidVersion, Version
        x, y = Version(a), Version(b)
    except Exception:
        return None
    return (x > y) - (x < y)


def compare(eco: str, a: str, b: str) -> Optional[int]:
    eco = (eco or '').lower()
    if not a or not b or not re.match(r'^v?\d', a) or not re.match(r'^v?\d', b):
        return None
    if eco in ('maven', 'java'):
        return maven_cmp(a, b)
    if eco in ('pypi', 'python'):
        c = pep440_cmp(a, b)
        return c if c is not None else semver_cmp(a, b)
    c = semver_cmp(a, b)
    if c is not None:
        return c
    return vercmp(a.lstrip('v'), b.lstrip('v'))
