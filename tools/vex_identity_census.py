"""Identity consistency: product_id vs purl, tag vs digest.

    python3 tools/vex_identity_census.py data/vex identity.json [workers]
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


def nodes_of(d):
    out = {}

    def walk(bs):
        for b in bs or []:
            p = b.get('product')
            if p:
                out[p['product_id']] = (p.get('product_identification_helper') or {}).get('purl', '')
            walk(b.get('branches'))
    walk((d.get('product_tree') or {}).get('branches'))
    return out


def one(fp):
    try:
        d = json.load(open(fp))
    except Exception:
        return None
    cve = os.path.basename(fp)[:-5]
    R = collections.defaultdict(C)
    EX = collections.defaultdict(dict)
    tags = collections.defaultdict(set)
    used = set()
    rel = {}
    for r in (d.get('product_tree') or {}).get('relationships') or []:
        rel[r['full_product_name']['product_id']] = r['product_reference']
    for v in d.get('vulnerabilities') or []:
        for ids in (v.get('product_status') or {}).values():
            used.update(rel.get(p, p) for p in ids)
    for pid, purl in nodes_of(d).items():
        if pid not in used or not purl:
            continue
        body = unquote(purl.split('?')[0])
        q = dict(kv.split('=', 1) for kv in purl.split('?', 1)[1].split('&') if '=' in kv) if '?' in purl else {}
        if purl.startswith('pkg:oci/'):
            pname = body[len('pkg:oci/'):].split('@')[0].split('/')[-1]
            repo = unquote(q.get('repository_url', '')).rstrip('/')
            rbase = repo.split('/')[-1] if repo else ''
            idname = re.sub(r'@.*$', '', pid).split('/')[-1]
            dg = '@sha256' in body
            k = ('digest' if dg else 'nodigest') + ': ' + (
                'pid==purl' if idname == pname else
                ('pid==purl(rhelN differs)' if re.sub(r'-rhel\d+', '', idname) == re.sub(r'-rhel\d+', '', pname) else
                 ('pid-is-brew-component' if idname.endswith('-container') else 'pid!=purl')))
            R['oci_pid_vs_purl'][k] += 1
            if 'pid==purl' != k.split(': ')[1]:
                R['oci_pid_vs_purl_ex_count'][k] += 0
                if len(EX['oci_pid_vs_purl']) < 400:
                    EX['oci_pid_vs_purl'].setdefault(k + ' #' + str(len(EX['oci_pid_vs_purl'])), f'{cve} {pid} :: {purl[:170]}')
            R['oci_repo_vs_purlname']['repo-basename==purlname' if rbase == pname else
                                      ('repo is namespace only' if repo and '/' in repo and rbase != pname and not repo.endswith(pname) else
                                       ('no repo' if not repo else 'repo!=name'))] += 1
            R['oci_host'][repo.split('/')[0] if repo else '-'] += 1
            if dg:
                dig = re.search(r'sha256[:%]3?A?([0-9a-f]{64})', purl.replace('%3A', ':'))
                if dig:
                    tags[dig.group(1)].add(unquote(q.get('tag', '')))
        elif purl.startswith('pkg:rpm/'):
            pname = body[len('pkg:rpm/'):].split('@')[0].split('/')[-1]
            comp = pid.split('::')[0]
            m = re.match(r'^(.*?)-(\d+):', comp)
            idname = m.group(1) if m else re.sub(r'\.src$', '', comp)
            R['rpm_pid_vs_purl']['same' if idname == pname else ('pid-has-path' if '/' in idname else 'differs')] += 1
            if idname != pname and len(EX['rpm_pid_vs_purl']) < 200:
                EX['rpm_pid_vs_purl'][f'#{len(EX["rpm_pid_vs_purl"])}'] = f'{cve} {pid} :: {purl[:150]}'
            R['rpm_qualifiers'][','.join(sorted(q))] += 1
            if 'distro' in q:
                R['rpm_distro'][unquote(q['distro'])[:40]] += 1
        else:
            t = purl[4:].split('/')[0]
            R['other_purl_types'][t] += 1
            if len(EX['other_purl_' + t]) < 30:
                EX['other_purl_' + t][str(len(EX['other_purl_' + t]))] = f'{cve} {pid} :: {purl[:150]}'
    for dg, ts in tags.items():
        R['digest_tag_count_in_file'][str(len(ts))] += 1
    return R, EX, {dg: sorted(ts) for dg, ts in tags.items()}


def main():
    files = sorted(glob.glob(os.path.join(sys.argv[1], 'CVE-*.json')))
    tot = collections.defaultdict(C)
    exs = collections.defaultdict(dict)
    dtags = collections.defaultdict(set)
    with Pool(int(sys.argv[3]) if len(sys.argv) > 3 else 4) as pool:
        for res in pool.imap_unordered(one, files, chunksize=8):
            if not res:
                continue
            R, EX, tg = res
            for k, c in R.items():
                tot[k].update(c)
            for k, e in EX.items():
                for s, v in e.items():
                    if len(exs[k]) < 400:
                        exs[k][s] = v
            for dg, ts in tg.items():
                if len(dtags[dg]) < 20:
                    dtags[dg].update(ts)
    multi = C(len(ts) for ts in dtags.values())
    kinds = C()
    for ts in dtags.values():
        k = tuple(sorted({'epoch' if re.match(r'^\d{9,11}$', t) else ('none' if not t else 'nvr') for t in ts}))
        kinds['+'.join(k) + (' (several)' if len(ts) > 1 else '')] += 1
    ex_multi = {dg: sorted(ts) for dg, ts in list(dtags.items()) if len(ts) > 1}
    out = {'counts': {k: dict(v.most_common()) for k, v in tot.items()},
           'digests': len(dtags), 'tags_per_digest_across_files': dict(sorted(multi.items())),
           'tag_kinds': dict(kinds.most_common()),
           'examples': exs, 'multi_tag_examples': dict(list(ex_multi.items())[:40])}
    json.dump(out, open(sys.argv[2], 'w'), indent=1)


if __name__ == '__main__':
    main()
