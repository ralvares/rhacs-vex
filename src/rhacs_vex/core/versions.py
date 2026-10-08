"""RPM version arithmetic and dist-tag decoding (VEX-MODEL §2, §3e, §6).

Pure functions, no VEX knowledge.  Every rule here was validated against the
corpus or rpm's own test vectors; see tests/test_engine_regressions.py §E/F/H/I.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional


# ── rpmvercmp / EVR ──────────────────────────────────────────────────────────

def rpmvercmp(a: str, b: str) -> int:
    """Segment-wise comparison of ONE version or release string.

    Port of rpm's lib/rpmvercmp.c: separators are skipped, numeric runs compare
    numerically, alpha runs lexically, a numeric run beats an alpha one, '~'
    sorts before everything (1.0~rc1 < 1.0) and '^' after (1.0^git1 > 1.0).
    """
    if a == b:
        return 0
    i, j, la, lb = 0, 0, len(a), len(b)
    while i < la or j < lb:
        while i < la and not (a[i].isalnum() or a[i] in '~^'):
            i += 1
        while j < lb and not (b[j].isalnum() or b[j] in '~^'):
            j += 1

        if (i < la and a[i] == '~') or (j < lb and b[j] == '~'):
            if i >= la or a[i] != '~':
                return 1
            if j >= lb or b[j] != '~':
                return -1
            i += 1
            j += 1
            continue
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

        si, sj = i, j
        isnum = a[i].isdigit()
        test = str.isdigit if isnum else str.isalpha
        while i < la and test(a[i]):
            i += 1
        while j < lb and test(b[j]):
            j += 1
        seg_a, seg_b = a[si:i], b[sj:j]
        if not seg_b:
            return 1 if isnum else -1
        if isnum:
            seg_a, seg_b = seg_a.lstrip('0') or '0', seg_b.lstrip('0') or '0'
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1

    if i >= la and j >= lb:
        return 0
    return 1 if i < la else -1


def vr_compare(a: str, b: str) -> int:
    """VERSION[-RELEASE]: version first, release only breaks a version tie.

    (version_utils decided '1.1.1-9.el8' > '1.1.1k-4.el8' on the release — a
    false suppression for every letter-suffixed upstream like openssl 1.1.1k.)
    """
    ver_a, _, rel_a = a.partition('-')
    ver_b, _, rel_b = b.partition('-')
    c = rpmvercmp(ver_a, ver_b)
    if c or not rel_a or not rel_b:
        return c
    return rpmvercmp(rel_a, rel_b)


def _split_epoch(v: str):
    if ':' in v:
        head, rest = v.split(':', 1)
        try:
            return int(head), rest
        except ValueError:
            return 0, v
    return 0, v


def evr_compare(a: str, b: str) -> int:
    """EPOCH:VERSION-RELEASE; a missing epoch is 0 and a higher epoch always wins."""
    ea, va = _split_epoch(a)
    eb, vb = _split_epoch(b)
    if ea != eb:
        return 1 if ea > eb else -1
    return vr_compare(va, vb)


def align_epochs(installed: str, fix: str) -> tuple:
    """Propagate an epoch present on one side to the other (§3e/§6e).

    VEX fix versions often omit the epoch the rpm carries; both name the same
    source package.
    """
    im = re.match(r'^(\d+):', installed)
    fm = re.match(r'^(\d+):', fix)
    if im and not fm:
        fix = f"{im.group(1)}:{fix}"
    elif fm and not im:
        installed = f"{fm.group(1)}:{installed}"
    return installed, fix


def installed_cmp(installed: str, fix: str) -> int:
    """evr_compare after epoch alignment — the comparison every fix check uses."""
    return evr_compare(*align_epochs(installed, fix))


# ── dist-tag decoding (§2) ───────────────────────────────────────────────────

def rhel_major(version: str) -> Optional[str]:
    """'…el8', '…+el8.4…' → '8'."""
    m = re.search(r'[.+]el(\d+)', version)
    return m.group(1) if m else None


def rhel_minor(version: str) -> Optional[str]:
    """'3.9.18-3.el9_4.10' → '4' · '…module+el8.10.0+…' → '10' · '…el8' → None."""
    m = re.search(r'\.el\d+_(\d+)', version)
    if m:
        return m.group(1)
    m = re.search(r'[.+]el(\d+)\.(\d+)\.', version)
    return m.group(2) if m else None


def lineage(version: str) -> tuple:
    """Build lineage of a version-release: ('rhaos','X.Y'), ('hum',None), ('el',suffix).

    OCP rpms (`rhaos4.21.el9`), Hardened Images (`hum1`) and layered products
    with their own dist-tag suffix (`el8pc` Satellite, `el9cp` Ceph, `el9ap`
    AAP, `el7a` Alt) version independently of base RHEL, so NEVRAs from
    different lineages never compare.
    """
    v = str(version or '')
    m = re.search(r'(?:^|[.+])rhaos(\d+\.\d+)(?:[.+]|$)', v)
    if m:
        return ('rhaos', m.group(1))
    if re.search(r'(?:^|[.+])hum\d*(?:[.+]|$)', v):
        return ('hum', None)
    m = re.search(r'[.+]el\d+(?:_\d+)?([a-z]+)', v)
    return ('el', m.group(1) if m else None)


def same_lineage(installed: str, candidate: str) -> bool:
    """May a VEX NEVRA be version-compared against the installed rpm?"""
    return lineage(installed) == lineage(candidate)


# ── module streams (§6d, §9.1a) ──────────────────────────────────────────────

def is_module_build(version: str) -> bool:
    return '.module+' in version or '+module+' in version


def module_stream_applies(pid: str, installed: str) -> bool:
    """Does a '::module:stream' PID apply to the installed version?

    A '.module+' install is compatible (the version compare decides).  With
    the marker normalised away, a numeric stream ('perl:5.32') must
    version-prefix the install and the RHEL major must agree; a non-numeric
    stream ('container-tools:rhel8') has nothing to verify against.
    Non-module PIDs always apply.
    """
    if '::' not in pid:
        return True
    if is_module_build(installed):
        return True
    tok = pid.split('::', 1)[1].rsplit(':', 1)[-1]
    if not re.fullmatch(r'\d+(\.\d+)*', tok):
        return False
    inst = installed.split(':', 1)[-1] if ':' in installed else installed
    if not (inst == tok or inst.startswith(tok + '.') or inst.startswith(tok + '-')):
        return False
    pid_el = (re.search(r'\.module\+el(\d+)', pid)
              or re.search(r'\.el(\d+)[._]', pid.split('::')[0]))
    inst_el = re.search(r'\.el(\d+)', inst)
    return not (pid_el and inst_el and pid_el.group(1) != inst_el.group(1))


# ── cross-stream fix inference (§6b exceptions) ──────────────────────────────

def upstream_newer_than_all(installed: str, fixes: Iterable[str]) -> bool:
    """Strictly newer than every fix on EPOCH:VERSION alone (release ignored).

    Releases are branch-local, versions are not: expat 2.5.0 on 9.8 cannot be
    missing a fix shipped in 2.2.10-12.el9_0.4.  Equal versions keep the
    release confound and return False.
    """
    seen = False
    for fix in fixes:
        inst, fx = align_epochs(installed, fix)
        # rpmvercmp treats ':' as a separator, so the aligned epoch is simply
        # the first numeric segment of each side.
        if rpmvercmp(inst.partition('-')[0], fx.partition('-')[0]) <= 0:
            return False
        seen = True
    return seen


def later_stream_than_all(installed: str, fixes: Iterable[str]) -> bool:
    """Installed on a later RHEL minor than every fix, and newer on full NEVRA.

    Red Hat fixes the current stream first and backports to EUS/E4S after, so a
    fix living only in older minors (or in mainline, the fork point) was already
    in the branch ours forked from.  Same major only; a fix in a newer stream is
    the ordinary "not backported yet" case.
    """
    major, minor = rhel_major(installed), rhel_minor(installed)
    if not (major and minor):
        return False
    seen = False
    for fix in fixes:
        if rhel_major(fix) != major:
            return False
        fminor = rhel_minor(fix)
        if fminor and int(fminor) >= int(minor):
            return False
        if installed_cmp(installed, fix) <= 0:
            return False
        seen = True
    return seen


# ── image build stamps (§5g corollary) ───────────────────────────────────────

def build_stamp(s: Optional[str]) -> Optional[int]:
    """Brew timestamp ('…202404030309…') or epoch-seconds tag → YYYYMMDDHHMM."""
    if not s:
        return None
    m = re.search(r'\b(20\d{10})\b', s)
    if m:
        return int(m.group(1))
    m = re.search(r'\b(1[5-9]\d{8})\b', s)
    if m:
        import time
        return int(time.strftime('%Y%m%d%H%M', time.gmtime(int(m.group(1)))))
    return None
