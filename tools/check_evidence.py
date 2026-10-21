"""Every triage row (vextriage scan --json) → its deciding product ids looked up in Red Hat's raw document.

    python3 tools/check_evidence.py data/scans/*/free.json data/scans/*/*-triage.json

A row whose rule says fixed / not affected / open must rest on a statement of that status.
"""
import json, gzip, sys, collections, os
VEX=os.environ.get('VEXTRIAGE_VEX', os.path.join('data', 'vex'))
EXPECT = {
 'fixed_ev': {'rpm_stream_fix','rpm_inherited','product_fix','product_past_fix','rpm_newer_version','rpm_past_mainline',
              'rpm_later_stream','rpm_errata','product_errata','image_later_fix','image_older_fix','image_unordered_fix','purl_fix'},
 'kna_ev': {'rpm_binary_clear','rpm_not_affected','rpm_clean_build','rpm_subpackage','product_not_affected','product_context',
            'image_clear','purl_not_affected','image_older_not_affected','image_newer_not_affected','vendor','rhel_code','image_line_clear' ,'image_own_clear'},
 'open_ev': {'rpm_open','product_open','image_line_open','image_own_open','purl_open','errata_assumed'},
}
_cache={}
def raw(cve):
    if cve not in _cache:
        p=f'{VEX}/{cve}.json.gz'
        if not os.path.exists(p): _cache[cve]=None; return None
        d=json.load(gzip.open(p)); m={}
        for v in d['vulnerabilities']:
            for st,ids in (v.get('product_status') or {}).items():
                for i in ids: m.setdefault(i,set()).add(st)
            for f in v.get('flags') or []:
                for i in f.get('product_ids') or []: m.setdefault(i,set()).add('known_not_affected:'+f.get('label',''))
        _cache[cve]=m
    return _cache[cve]
bad=collections.Counter(); ok=collections.Counter(); ex=collections.defaultdict(list)
for f in sys.argv[1:]:
    for r in json.load(open(f)):
        rule=r['rule']; ev=r.get('evidence') or []
        if not ev: continue
        m=raw(r['cve'])
        if m is None: bad[(rule,'no-doc')]+=1; continue
        sts=set().union(*[m.get(e,set()) for e in ev])
        if not sts: bad[(rule,'pid-not-in-doc')]+=1; ex[(rule,'pid-not-in-doc')].append((r['cve'],ev[0])); continue
        want = 'fixed' if rule in EXPECT['fixed_ev'] else 'known_not_affected' if rule in EXPECT['kna_ev'] else \
               ('known_affected','under_investigation') if rule in EXPECT['open_ev'] else None
        if rule in ('rpm_exact','product_exact','this_build','image_build','purl_exact'):
            want = {'fixed':'fixed','not_affected':'known_not_affected'}.get(r['status'], ('known_affected','under_investigation'))
        if want is None: ok[(rule,'unchecked')]+=1; continue
        wants = want if isinstance(want, tuple) else (want,)
        if any(s.split(':')[0] in wants for s in sts): ok[(rule,'ok')]+=1
        else: bad[(rule,'status '+','.join(sorted(sts)))]+=1; ex[(rule,'status')].append((r['cve'],r['package'],ev[0],sorted(sts)))
print('checked ok:', sum(v for k,v in ok.items() if k[1]=='ok'), ' unchecked:', dict((k[0],v) for k,v in ok.items() if k[1]=='unchecked'))
print('mismatch:', dict(bad))
for k,v in ex.items(): print(k, v[:3])
