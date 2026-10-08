"""Census of Red Hat CSAF-VEX: how statements are shaped per stream / product class.

    python3 tools/vex_census.py data/vex census.json [workers]
"""
import collections
import glob
import json
import os
import re
import sys
from multiprocessing import Pool
from urllib.parse import unquote

C = collections.Counter


def walk(branches, path, out):
    for b in branches or []:
        cat = b.get('category', '')
        p = b.get('product')
        np = path + (cat,)
        if p:
            h = p.get('product_identification_helper') or {}
            out[p['product_id']] = (np, p.get('name', ''), h.get('purl', ''), h.get('cpe', ''))
        walk(b.get('branches'), np, out)


def dist(ver):
    v = unquote(ver)
    m = re.search(r'\.(module\+el\d+\.\d+)', v)
    if m:
        return m.group(1).replace(r'\d', 'N')
    m = re.search(r'(rhaos\d+\.\d+\.el\d+(?:_\d+)?)', v)
    if m:
        return re.sub(r'\d+\.\d+', 'X.Y', m.group(1), count=1)
    m = re.search(r'\.(el\d+(?:_\d+)?[a-z]*)', v)
    if m:
        return m.group(1)
    m = re.search(r'\.(hum\d*)', v)
    if m:
        return m.group(1)
    return 'other'


_RHEL_REPO = r'(?:AppStream|BaseOS|CRB|HighAvailability|RT|NFV|ResilientStorage|SAP|SAPHANA|Supplementary|[A-Za-z]+)'


def parent_class(cpe, name, pid):
    pid = pid or ''
    if re.match(r'^red_hat_enterprise_linux_\d+$', pid):
        return 'rhel-neutral'
    m = re.match(_RHEL_REPO + r'-(\d+)\.(\d+)(?:\.\d+)?\.?(.*)$', pid)
    if m and 'enterprise_linux' in (cpe or '') or (m and re.match(r'cpe:/[ao]:redhat:rhel_', cpe or '')):
        return 'rhel-minor:' + (m.group(3) or 'plain')
    if re.match(r'^\d+(Server|Client|Workstation|ComputeNode|AS|ES|WS|Desktop)', pid):
        return 'rhel-legacy'
    if re.match(r'^\d+Base-RHOSE-\d', pid):
        return 'ocp-stream'
    if pid.startswith('red_hat_openshift_container_platform_'):
        return 'ocp-neutral'
    if re.match(r'^Red Hat OpenShift Container Platform \d', pid):
        return 'ocp-named-minor'
    if re.match(r'^\d+Base-', pid):
        return 'layered-stream'
    c = cpe or ''
    if c == 'cpe:/a:redhat':
        return 'catchall'
    m = re.match(r'cpe:/([ao]):redhat:([a-z0-9_]+)(?::([^:]*))?(?::([^:]*))?(?::(.*))?', c)
    if not m:
        return 'nocpe:' + re.sub(r'[\d.]+', 'N', pid.split(':')[0])[:40]
    part, prod, ver, upd, ed = m.groups()
    ver = ver or ''
    if prod in ('enterprise_linux', 'rhel_eus', 'rhel_e4s', 'rhel_aus', 'rhel_tus',
                'rhel_els', 'rhel_extras', 'rhel_els_extended'):
        kind = 'rhel-minor' if re.match(r'^\d+\.\d+', ver) else ('rhel-major' if ver else 'rhel-any')
        return f'{kind}:{prod}' + (f'::{ed}' if ed and ed not in ('baseos', 'appstream', 'crb', 'base') else '')
    if prod == 'openshift':
        if re.match(r'^\d+\.\d+', ver):
            return 'ocp-minor' + ('::' + re.sub(r'\d+', 'N', ed) if ed else '')
        return 'ocp-major' if ver else 'ocp-any'
    return 'layered:' + ('ver' if ver else 'nover')


def comp_class(purl, comp):
    if not purl:
        if '/' in comp:
            return 'nopurl-path'
        return 'nopurl'
    t = purl[4:].split('/')[0]
    body = purl.split('?')[0]
    q = dict(kv.split('=', 1) for kv in purl.split('?', 1)[1].split('&')) if '?' in purl else {}
    if t == 'rpm':
        name = unquote(body[len('pkg:rpm/'):]).split('@')[0]
        ns_path = name.count('/') > 1
        ver = unquote(body.split('@', 1)[1]) if '@' in body else ''
        k = 'rpm' + ('-path' if ns_path else '') + (('@' + dist(ver)) if ver else '-nover')
        if q.get('arch') == 'src':
            k += '.src'
        if 'rpmmod' in q:
            k += '+mod'
        return k
    if t == 'oci':
        digest = '@sha256:' in body
        tag = unquote(q.get('tag', ''))
        if not tag:
            tk = 'notag'
        elif re.match(r'^\d{9,11}$', tag):
            tk = 'tag-epoch'
        elif re.match(r'^v?\d+\.\d+(\.\d+)?-\d{12}', tag):
            tk = 'tag-vX.Y-stamp'
        elif re.match(r'^v?\d+\.\d+(\.\d+)?-\d+', tag):
            tk = 'tag-vX.Y-N'
        elif re.match(r'^v?\d+\.\d+(\.\d+)?$', tag):
            tk = 'tag-vX.Y'
        else:
            tk = 'tag-other'
        ns = '/' in body[len('pkg:oci/'):].split('@')[0]
        return 'oci' + ('@digest' if digest else '-nodigest') + ('-nsname' if ns else '') + '-' + tk
    return t


def one(fp):
    try:
        d = json.load(open(fp))
    except Exception:
        return None
    cve = os.path.basename(fp)[:-5]
    nodes = {}
    pt = d.get('product_tree') or {}
    walk(pt.get('branches'), (), nodes)
    rel = {}
    for r in pt.get('relationships') or []:
        rel[r['full_product_name']['product_id']] = (r['product_reference'],
                                                    r['relates_to_product_reference'],
                                                    r.get('category'))
    R = collections.defaultdict(C)
    EX = collections.defaultdict(dict)

    def ex(k, sub, v):
        if len(EX[k]) < 6 and sub not in EX[k]:
            EX[k][sub] = v

    for r in rel.values():
        R['rel_category'][r[2]] += 1
    for pid, (path, name, purl, cpe) in nodes.items():
        R['branch_path'][' > '.join(path)] += 1
    for v in d.get('vulnerabilities') or []:
        ps = v.get('product_status') or {}
        rem = collections.defaultdict(set)
        for r in v.get('remediations') or []:
            for p in r.get('product_ids') or []:
                rem[p].add((r['category'], (r.get('details') or '')[:40] if r['category'] in ('no_fix_planned', 'none_available') else ''))
        flagged = {p for f in v.get('flags') or [] for p in f.get('product_ids') or []}
        R['statuses_present'][','.join(sorted(k for k, x in ps.items() if x))] += 1
        per_pkg = collections.defaultdict(set)      # (rpm name) -> {(status, parentclass)}
        oci_img = collections.defaultdict(set)      # image key -> {(status, pclass, digest?)}
        seen = {}
        for st, ids in ps.items():
            for pid in ids:
                if pid in seen and seen[pid] != st:
                    R['pid_in_two_statuses'][f'{seen[pid]}+{st}'] += 1
                    ex('pid_in_two_statuses', f'{seen[pid]}+{st}', f'{cve} {pid}')
                seen[pid] = st
                if pid in rel:
                    comp, parent, _ = rel[pid]
                else:
                    comp, parent = pid, None
                cnode = nodes.get(comp, ((), '', '', ''))
                pnode = nodes.get(parent, ((), '', '', '')) if parent else ((), '', '', '')
                pc = parent_class(pnode[3], pnode[1], parent or '') if parent else 'bare:' + parent_class(cnode[3], cnode[1], pid)
                cc = comp_class(cnode[2], comp)
                R['status_x_parent_x_comp'][f'{st} | {pc} | {cc}'] += 1
                ex('status_x_parent_x_comp', f'{st} | {pc} | {cc}', f'{cve} {pid} :: {cnode[2][:160]}')
                for cat, det in rem.get(pid, ()):
                    R['remediation'][f'{st} | {cat} {det} | {pc.split(":")[0]} | {cc.split("@")[0].split("-")[0]}'] += 1
                if pid in flagged:
                    R['flagged_status'][f'{st} | {cc.split("@")[0]}'] += 1
                purl = cnode[2]
                if purl.startswith('pkg:rpm/'):
                    name = unquote(purl.split('?')[0][len('pkg:rpm/'):]).split('@')[0]
                    name = name.split('/', 1)[1] if '/' in name else name
                    ver = unquote(purl.split('?')[0].split('@', 1)[1]) if '@' in purl.split('?')[0] else ''
                    mj = (re.search(r'el(\d+)', ver) or re.search(r'(?:linux_|^|-)(\d+)(?:Base|Server|Client|Workstation|\.|$)', parent or '')
                          or re.search(r'el(\d+)', pnode[3] or ''))
                    mj = mj.group(1) if mj else '?'
                    per_pkg[(name, mj)].add((st, pc.split(':')[0] + (':' + re.sub(r'el\d+', 'elN', dist(ver)) if ver else ':nover')))
                    # parent minor vs dist minor
                    if st == 'fixed' and ver:
                        pm = re.match(r'(?:\w+-)?(\d+)\.(\d+)', parent or '')
                        dm = re.search(r'el(\d+)_(\d+)', ver) or re.search(r'module\+el(\d+)\.(\d+)', ver)
                        dg = re.search(r'\.el(\d+)(?![_\d])', ver)
                        if pm and dm:
                            R['fixed_parentminor_vs_distminor']['same' if pm.groups() == dm.groups() else
                                                               ('dist-older' if (int(dm.group(1)), int(dm.group(2))) < (int(pm.group(1)), int(pm.group(2))) else 'dist-newer')] += 1
                            if pm.groups() != dm.groups():
                                ex('fixed_parentminor_vs_distminor', parent.split(':')[0] + '/' + dist(ver), f'{cve} {pid}')
                        elif pm and dg:
                            R['fixed_parentminor_vs_distminor']['dist-bare-el (parent has minor)'] += 1
                            ex('fixed_parentminor_vs_distminor', 'bare:' + re.sub(r'\d', 'N', parent.split(':')[0]), f'{cve} {pid}')
                elif purl.startswith('pkg:oci/'):
                    body = purl.split('?')[0][len('pkg:oci/'):]
                    nm = body.split('@')[0].split('/')[-1]
                    oci_img[nm].add((st, pc.split(':')[0].split('::')[0], '@sha256:' in body))
                    q = dict(kv.split('=', 1) for kv in purl.split('?', 1)[1].split('&')) if '?' in purl else {}
                    host = unquote(q.get('repository_url', '')).split('/')[0] or 'none'
                    pd_ = '@sha256' in body
                    pidd = '@sha256:' in pid
                    R['oci_digest_where'][f'{st} | pid:{"D" if pidd else "-"} purl:{"D" if pd_ else "-"} | {host}'] += 1
                    ex('oci_digest_where', f'{st} | pid:{"D" if pidd else "-"} purl:{"D" if pd_ else "-"} | {host}', f'{cve} {pid} :: {purl[:150]}')
                    R['oci_parent_kind'][f'{st} | {pc} | {"D" if pidd else "-"}'] += 1
                    ex('oci_parent_kind', f'{st} | {pc} | {"D" if pidd else "-"}', f'{cve} {pid}')
        for name, sig in per_pkg.items():
            key = ' ; '.join(sorted({f'{s}:{p}' for s, p in sig}))
            R['rpm_pkg_signature'][key] += 1
            ex('rpm_pkg_signature', key, f'{cve} {name[0]} el{name[1]}')
            sts = {s for s, p in sig}
            R['rpm_pkg_status_set'][','.join(sorted(sts))] += 1
            # KA on a RHEL-major (neutral) node together with fixed minors?
            if any(s == 'known_affected' and p.startswith('rhel-neutral') for s, p in sig):
                R['rhel_major_KA_with'][','.join(sorted({s + ':' + p.split(':')[0] for s, p in sig if not (s == 'known_affected' and p.startswith('rhel-neutral'))})) or 'alone'] += 1
        for nm, sig in oci_img.items():
            key = ' ; '.join(sorted({f'{s}:{p}:{"D" if dg else "N"}' for s, p, dg in sig}))
            R['oci_image_signature'][key] += 1
            ex('oci_image_signature', key, f'{cve} {nm}')
    return R, EX


def main():
    files = sorted(glob.glob(os.path.join(sys.argv[1], 'CVE-*.json')))
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 6
    tot = collections.defaultdict(C)
    exs = collections.defaultdict(dict)
    n = 0
    with Pool(workers) as pool:
        for res in pool.imap_unordered(one, files, chunksize=8):
            if not res:
                continue
            n += 1
            R, EX = res
            for k, c in R.items():
                tot[k].update(c)
            for k, e in EX.items():
                for s, v in e.items():
                    if s not in exs[k] and len(exs[k]) < 4000:
                        exs[k][s] = v
            if n % 1000 == 0:
                print(n, file=sys.stderr)
    out = {'files': n, 'counts': {k: dict(v.most_common()) for k, v in tot.items()},
           'examples': exs}
    json.dump(out, open(sys.argv[2], 'w'), indent=1)


if __name__ == '__main__':
    main()
