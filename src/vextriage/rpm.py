"""RPM versions: rpmvercmp, EVR comparison and what a release's dist tag says.

    >>> evr_cmp('1:3.0.7-27.el9', '1:3.0.7-24.el9_4')
    1
    >>> dist('2.34-100.el9_4.12')
    Dist(major=9, minor=4, module=False, token='el')
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import NamedTuple, Optional


def _alnum(c: str) -> bool:
    return c.isascii() and c.isalnum()


def vercmp(a: str, b: str) -> int:
    """rpm's rpmvercmp: -1, 0 or 1."""
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        while i < la and not _alnum(a[i]) and a[i] not in '~^':
            i += 1
        while j < lb and not _alnum(b[j]) and b[j] not in '~^':
            j += 1
        # '~' sorts before anything, even the end of the string
        if (i < la and a[i] == '~') or (j < lb and b[j] == '~'):
            if i >= la or a[i] != '~':
                return 1
            if j >= lb or b[j] != '~':
                return -1
            i, j = i + 1, j + 1
            continue
        # '^' sorts after the end of the string, before anything else
        if (i < la and a[i] == '^') or (j < lb and b[j] == '^'):
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if a[i] != '^':
                return 1
            if b[j] != '^':
                return -1
            i, j = i + 1, j + 1
            continue
        if i >= la or j >= lb:
            break
        num = a[i].isdigit()
        si, sj = i, j
        if num:
            while i < la and a[i].isdigit():
                i += 1
            while j < lb and b[j].isdigit():
                j += 1
        else:
            while i < la and a[i].isascii() and a[i].isalpha():
                i += 1
            while j < lb and b[j].isascii() and b[j].isalpha():
                j += 1
        x, y = a[si:i], b[sj:j]
        if not y:                       # numeric segments beat alpha ones
            return 1 if num else -1
        if num:
            x, y = x.lstrip('0'), y.lstrip('0')
            if len(x) != len(y):
                return 1 if len(x) > len(y) else -1
        if x != y:
            return 1 if x > y else -1
    if i >= la and j >= lb:
        return 0
    return -1 if i >= la else 1


class EVR(NamedTuple):
    epoch: Optional[int]        # None: not stated (takes the other side's)
    version: str
    release: str

    def __str__(self) -> str:
        e = f'{self.epoch}:' if self.epoch else ''
        return f'{e}{self.version}-{self.release}' if self.release else f'{e}{self.version}'


def parse_evr(s: str, epoch: Optional[int] = None) -> EVR:
    """'1:3.0.7-27.el9' or '3.0.7-27.el9' (+ an epoch given apart)."""
    s = s.replace('%2B', '+').replace('%2b', '+')
    if ':' in s:
        e, s = s.split(':', 1)
        epoch = int(e) if e.isdigit() else epoch
    v, _, r = s.rpartition('-') if '-' in s else (s, '', '')
    return EVR(epoch, v, r)


def evr_cmp(a, b) -> int:
    """Compare EVRs (or strings). An epoch stated on one side only is taken
    for both: VEX writes `openssl-1:3.0.7` where a scanner may drop the 1."""
    a = parse_evr(a) if isinstance(a, str) else a
    b = parse_evr(b) if isinstance(b, str) else b
    ea = a.epoch if a.epoch is not None else (b.epoch or 0)
    eb = b.epoch if b.epoch is not None else (a.epoch or 0)
    if ea != eb:
        return 1 if ea > eb else -1
    c = vercmp(a.version, b.version)
    if c or not (a.release and b.release):
        return c
    return vercmp(a.release, b.release)


def ev_cmp(a: EVR, b: EVR) -> int:
    """Epoch and upstream version only — release numbers are branch-local."""
    ea = a.epoch if a.epoch is not None else (b.epoch or 0)
    eb = b.epoch if b.epoch is not None else (a.epoch or 0)
    if ea != eb:
        return 1 if ea > eb else -1
    return vercmp(a.version, b.version)


@dataclass(frozen=True)
class Dist:
    major: Optional[int]
    minor: Optional[int]        # el9_4 → 4, module+el8.6.0 → 6; plain el9 → None
    module: bool                # a module build (.module+elN.M.0+…)
    token: str                  # 'el' (RHEL), 'module', 'rhaos4.20', 'elap', 'elsat', 'hum', '' …


_MODULE = re.compile(r'module\+el(\d+)\.(\d+)\.\d+')
_RHAOS = re.compile(r'rhaos(\d+\.\d+)\b.*?\.el(\d+)')
_EL = re.compile(r'\.el(\d+)(?:_(\d+))?([a-z]*)')
_HUM = re.compile(r'\.hum\d')


def dist(release: str) -> Dist:
    """What the dist tag of a release says (an EVR string works too)."""
    rel = release.replace('%2B', '+').replace('%2b', '+').rsplit('-', 1)[-1]
    m = _MODULE.search(rel)
    if m:
        return Dist(int(m.group(1)), int(m.group(2)), True, 'module')
    m = _RHAOS.search(rel)
    if m:
        return Dist(int(m.group(2)), None, False, 'rhaos' + m.group(1))
    m = _EL.search(rel)
    if m:
        minor = int(m.group(2)) if m.group(2) else None
        return Dist(int(m.group(1)), minor, False, 'el' + m.group(3))
    if _HUM.search(rel):
        return Dist(None, None, False, 'hum')
    return Dist(None, None, False, '')


def source_name(source_rpm: str) -> str:
    """'openssl-3.0.7-27.el9.src.rpm' → 'openssl'."""
    s = re.sub(r'\.(src|nosrc)\.rpm$', '', source_rpm or '')
    parts = s.rsplit('-', 2)
    return parts[0] if len(parts) == 3 else ''


def source_vr(source_rpm: str) -> str:
    """'openssl-3.0.7-27.el9.src.rpm' → '3.0.7-27.el9'."""
    s = re.sub(r'\.(src|nosrc)\.rpm$', '', source_rpm or '')
    parts = s.rsplit('-', 2)
    return f'{parts[1]}-{parts[2]}' if len(parts) == 3 else ''
