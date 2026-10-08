#!/usr/bin/env python3
"""Differential fuzz: the frozen legacy engine vs the current one.

Generates synthetic Red Hat CSAF-VEX documents in the shapes VEX-MODEL.md
documents (RHEL base streams, RHOSE streams, version-neutral OCP, layered
products, digest-pinned and generic image PIDs in both OCI-purl eras, .src and
module PIDs, flags, remediations, threats, the vendor catch-all) and runs random
workloads x findings through both engines.  Any difference in the six verdict
values or the VEX_PRODUCT label is printed and fails the run.

    python3 tests/fuzz_engine_diff.py [--docs N] [--rows N] [--seed S]

The real-corpus counterpart is tests/diff_engines_corpus.py.
"""
import argparse
import copy
import collections
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'src'))
sys.path.insert(0, ROOT)

from tests.legacy import engine_legacy as old   # noqa: E402
from rhacs_vex import engine as new             # noqa: E402

# ── vocabulary ───────────────────────────────────────────────────────────────

PRODUCTS = [
    # (pid, name, cpe)
    ('AppStream-9.4.0.Z.EUS', 'Red Hat Enterprise Linux AppStream EUS (v.9.4)',
     'cpe:/a:redhat:rhel_eus:9.4::appstream'),
    ('BaseOS-9.6.0.Z.MAIN', 'Red Hat Enterprise Linux BaseOS (v. 9)',
     'cpe:/o:redhat:enterprise_linux:9::baseos'),
    ('AppStream-9.0.0.Z.E4S', 'Red Hat Enterprise Linux AppStream E4S (v.9.0)',
     'cpe:/a:redhat:rhel_e4s:9.0::appstream'),
    ('red_hat_enterprise_linux_9', 'Red Hat Enterprise Linux 9',
     'cpe:/o:redhat:enterprise_linux:9'),
    ('red_hat_enterprise_linux_8', 'Red Hat Enterprise Linux 8',
     'cpe:/o:redhat:enterprise_linux:8'),
    ('AppStream-8.10.0.Z.MAIN.EUS', 'Red Hat Enterprise Linux AppStream (v. 8)',
     'cpe:/a:redhat:enterprise_linux:8::appstream'),
    ('BaseOS-8.5.0.GA', 'Red Hat Enterprise Linux BaseOS (v. 8)',
     'cpe:/o:redhat:enterprise_linux:8::baseos'),
    ('9Base-RHOSE-4.16', 'Red Hat OpenShift Container Platform 4.16',
     'cpe:/a:redhat:openshift:4.16::el9'),
    ('8Base-RHOSE-4.12', 'Red Hat OpenShift Container Platform 4.12',
     'cpe:/a:redhat:openshift:4.12::el8'),
    ('red_hat_openshift_container_platform_4', 'Red Hat OpenShift Container Platform 4',
     'cpe:/a:redhat:openshift:4'),
    ('8Base-satellite-6.16', 'Red Hat Satellite 6.16 for RHEL 8',
     'cpe:/a:redhat:satellite:6.16::el8'),
    ('9Base-Fast-Datapath', 'Fast Datapath for RHEL 9',
     'cpe:/o:redhat:enterprise_linux:9::fastdatapath'),
    ('Red Hat OpenShift AI 2.16', 'Red Hat OpenShift AI 2.16',
     'cpe:/a:redhat:openshift_ai:2.16::el9'),
    ('red_hat_web_terminal', 'Red Hat Web Terminal', 'cpe:/a:redhat:webterminal:1'),
    ('Red Hat Web Terminal 1.11', 'Red Hat Web Terminal 1.11',
     'cpe:/a:redhat:webterminal:1.11::el9'),
    ('8Base-RHACM-2.9', 'Red Hat Advanced Cluster Management for Kubernetes 2.9 for RHEL 8',
     'cpe:/a:redhat:acm:2.9::el8'),
    ('red_hat_jboss_enterprise_application_platform_5', 'Red Hat JBoss EAP 5',
     'cpe:/a:redhat:jboss_enterprise_application_platform:5'),
    ('3AS', 'Red Hat Enterprise Linux AS version 3', 'cpe:/o:redhat:enterprise_linux:3::as'),
    ('Red Hat Hardened Images', 'Red Hat Hardened Images', 'cpe:/a:redhat:hummingbird:1'),
]
CATCHALL = ('red_hat_products', 'All currently supported Red Hat products', 'cpe:/a:redhat')

RPM_NAMES = ['openssl', 'openssl-libs', 'curl', 'curl-minimal', 'glibc', 'libsmartcols',
             'util-linux', 'perl-libs', 'perl', 'python3', 'python3-libs',
             'python3-chardet', 'python-chardet', 'buildah', 'libsolv', 'expat',
             'openshift-clients', 'krb5-libs', 'tar', 'podman']
DIST = ['el9', 'el9_0', 'el9_4', 'el9_6', 'el9_8', 'el8', 'el8_6', 'el8_10', 'el8pc',
        'el9cp', 'el9ap', 'rhaos4.16.el9', 'rhaos4.12.el8', 'hum1',
        'module+el8.10.0+21354+3ad137bb']
ARCHES = ['x86_64', 'aarch64', 'ppc64le', 's390x', 'noarch', 'src']
IMAGES = ['openshift4/ose-cli-rhel9', 'openshift4/ose-cli-rhel8', 'openshift4/ose-cli',
          'openshift4/ose-etcd-rhel9', 'openshift4/ose-cluster-etcd-rhel9-operator',
          'rhoai/odh-model-controller-rhel9', 'rhoai/odh-notebook-rhel8',
          'web-terminal/web-terminal-tooling-rhel9', 'web-terminal/web-terminal-exec-rhel9',
          'openshift/ose-cli-rhel9', 'rhacm2/console-rhel9']
GENERICS = ['rhcos', 'jackson-databind']
SHAS = ['a' * 64, 'b' * 64, 'c' * 64, 'd' * 64, 'e' * 64]
STAMPS = ['v4.16.0-202404030309.p0.el9', '1781813947', 'v4.12.0-202301010000.p0',
          '1600000000', 'latest']
GO_COMPS = ['golang.org/x/net', 'github.com/sigstore/fulcio', 'stdlib']
JAVA = ['com.fasterxml.jackson.core:jackson-databind', 'io.netty:netty-codec']
FLAGS = ['vulnerable_code_not_present', 'component_not_present',
         'vulnerable_code_not_in_execute_path', 'inline_mitigations_already_exist']
STATUSES = ['known_affected', 'known_not_affected', 'fixed', 'under_investigation']
SEVS = ['Critical', 'Important', 'Moderate', 'Low']


def rversion(rng, name=None):
    up = rng.choice(['1.1.1', '1.1.1k', '2.34', '3.0.7', '0.7.20', '0.7.22', '2.5.0',
                     '2.2.10', '5.32.1', '4.14.0', '3.9.21', '4.0.0', '2.37.4'])
    rel = rng.choice(['1', '6', '12', '28', '60', '272', '473', '474'])
    dist = rng.choice(DIST)
    if rng.random() < 0.2:
        rel += '.' + rng.choice(['1', '4', '12'])
    return f"{up}-{rel}.{dist}"


SEEN_RPMS = []


def rcomponent(rng):
    """(component_pid, purl|None) for one product-tree leaf."""
    kind = rng.choices(['nevra', 'src', 'leaf', 'leafsrc', 'module', 'image_digest',
                        'image_plain', 'image_url', 'generic', 'humm'],
                       [30, 8, 8, 5, 5, 14, 10, 6, 4, 2])[0]
    name = rng.choice(RPM_NAMES)
    if kind == 'nevra':
        vr = rversion(rng)
        arch = rng.choice(ARCHES[:-1])
        ep = rng.choice(['0', '0', '1', '4', '32'])
        pid = f"{name}-{ep}:{vr}.{arch}"
        SEEN_RPMS.append((name, vr, ep))
        purl = None if rng.random() < 0.15 else \
            f"pkg:rpm/redhat/{name}@{vr.replace('+', '%2B')}?arch={arch}" + \
            (f"&epoch={ep}" if ep != '0' else '')
        return pid, purl
    if kind == 'src':
        vr = rversion(rng)
        SEEN_RPMS.append((name, vr, '0'))
        return f"{name}-0:{vr}.src", f"pkg:rpm/redhat/{name}@{vr}?arch=src"
    if kind == 'leaf':
        return name, (None if rng.random() < 0.3 else f"pkg:rpm/redhat/{name}")
    if kind == 'leafsrc':
        return f"{name}.src", f"pkg:rpm/redhat/{name}?arch=src"
    if kind == 'module':
        vr = rng.choice(['5.32.1-473.module+el8.10.0+21354+3ad137bb',
                         '5.32.1-472.module+el8.10.0+1+2', '4.4.1-1.module+el8.10.0+1'])
        stream = rng.choice(['perl:5.32', 'perl:5.26', 'container-tools:rhel8'])
        nm = rng.choice(['perl-libs', 'perl', 'podman'])
        return (f"{nm}-4:{vr}.x86_64::{stream}",
                f"pkg:rpm/redhat/{nm}@{vr.replace('+', '%2B')}?arch=x86_64&rpmmod={stream}")
    img = rng.choice(IMAGES)
    ns, short = img.split('/', 1)
    tag = rng.choice(STAMPS)
    if kind == 'image_digest':
        sha = rng.choice(SHAS)
        arch = rng.choice(['amd64', 'arm64', 'ppc64le'])
        if rng.random() < 0.5:   # old era
            purl = (f"pkg:oci/{short}@sha256:{sha}?arch={arch}"
                    f"&repository_url=registry.redhat.io/{img}&tag={tag}")
        else:                    # Konflux era
            purl = (f"pkg:oci/{img}@sha256:{sha}?arch={arch}"
                    f"&repository_url=registry.redhat.io/{ns}&tag={tag}")
        return f"{img}@sha256:{sha}_{arch}", purl
    if kind == 'image_url':
        sha = rng.choice(SHAS)
        return (f"registry.redhat.io/{img}@sha256:{sha}_amd64",
                f"pkg:oci/{short}@sha256:{sha}?arch=amd64"
                f"&repository_url=registry.redhat.io/{img}&tag={tag}")
    if kind == 'image_plain':
        return img, (None if rng.random() < 0.3 else
                     f"pkg:oci/{short}?repository_url=registry.redhat.io/{img}")
    if kind == 'generic':
        g = rng.choice(GENERICS)
        return g, f"pkg:generic/redhat/{g}"
    return (f"{rng.choice(['curl', 'perl'])}-main@x86_64",
            f"pkg:rpm/redhat/curl@8.21.0-0.1.1.hum1?arch=x86_64")


def rdoc(rng):
    nprod = rng.randint(1, 6)
    prods = rng.sample(PRODUCTS, nprod)
    catch = rng.random() < 0.05
    if catch:
        prods.append(CATCHALL)
    branches = [{'product': {'product_id': p, 'name': n,
                             'product_identification_helper': {'cpe': c}}}
                for p, n, c in prods]
    leaves, rels, fpids = {}, [], []
    for p, _n, _c in prods:
        if p == 'red_hat_products':
            fpids.append(p)
            continue
        for _ in range(rng.randint(1, 8)):
            comp, purl = rcomponent(rng)
            if comp not in leaves:
                leaves[comp] = purl
            fp = f"{p}:{comp}"
            rels.append({'category': 'default_component_of', 'product_reference': comp,
                         'relates_to_product_reference': p,
                         'full_product_name': {'product_id': fp, 'name': fp}})
            fpids.append(fp)
    leaf_nodes = []
    for comp, purl in leaves.items():
        node = {'product_id': comp, 'name': comp}
        if purl:
            node['product_identification_helper'] = {'purl': purl}
        leaf_nodes.append({'product': node})
    tree = {'branches': [{'category': 'vendor', 'name': 'Red Hat',
                          'branches': branches + leaf_nodes}],
            'relationships': rels}
    vulns = []
    for _ in range(1 if rng.random() < 0.9 else 2):
        ps = collections.defaultdict(list)
        for fp in fpids:
            if rng.random() < 0.85:
                st = rng.choices(STATUSES, [35, 30, 30, 5])[0]
                if fp == 'red_hat_products':
                    st = 'known_not_affected'
                ps[st].append(fp)
        flags = []
        kna = ps.get('known_not_affected', [])
        if kna and rng.random() < 0.5:
            flags.append({'label': rng.choice(FLAGS),
                          'product_ids': rng.sample(kna, rng.randint(1, len(kna)))})
        others = [f for f in fpids if rng.random() < 0.1]
        if others:
            flags.append({'label': rng.choice(FLAGS), 'product_ids': others})
        rems = []
        ka = ps.get('known_affected', [])
        if ka and rng.random() < 0.6:
            cat, det = rng.choice([('no_fix_planned', 'Will not fix'),
                                   ('no_fix_planned', 'Out of support scope'),
                                   ('none_available', 'Fix deferred'),
                                   ('none_available', 'Affected')])
            rems.append({'category': cat, 'details': det,
                         'product_ids': rng.sample(ka, rng.randint(1, len(ka)))})
        if ps.get('fixed') and rng.random() < 0.7:
            rems.append({'category': 'vendor_fix', 'details': 'RHSA',
                         'product_ids': list(ps['fixed'])})
        threats = []
        for sev in rng.sample(SEVS, rng.randint(0, 3)):
            pool = fpids
            threats.append({'category': 'impact', 'details': sev,
                            'product_ids': rng.sample(pool, rng.randint(1, len(pool)))})
        scores = []
        if rng.random() < 0.5:
            scores.append({'cvss_v3': {'baseSeverity': rng.choice(['HIGH', 'MEDIUM', 'LOW', 'CRITICAL'])},
                           'products': fpids[:3]})
        vulns.append({'cve': 'CVE-2099-0001', 'product_status': dict(ps), 'flags': flags,
                      'remediations': rems, 'threats': threats, 'scores': scores})
    doc = {'document': {'aggregate_severity': {'text': rng.choice(['', 'Moderate', 'Important'])}},
           'product_tree': tree, 'vulnerabilities': vulns}
    if rng.random() < 0.05:
        doc['vulnerabilities'] = []
    return doc


def rworkload(rng, mod):
    """A context built through the module's own parsers, as callers do."""
    sha = rng.choice(SHAS) if rng.random() < 0.3 else 'f' * 64
    shape = rng.choice(['ubi', 'ocp_artdev', 'ocp_registry', 'operator', 'operator_label',
                        'ubi8'])
    labels = {}
    if shape == 'ubi':
        ref = f"registry.access.redhat.com/ubi9/ubi@sha256:{sha}"
    elif shape == 'ubi8':
        ref = f"registry.access.redhat.com/ubi8/ubi-minimal@sha256:{sha}"
    elif shape == 'ocp_artdev':
        ref = f"quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:{sha}"
        img = rng.choice(['openshift/ose-cli-rhel9', 'openshift/ose-etcd-rhel9',
                          'openshift/ose-cli-rhel8'])
        labels = {'name': img, 'cpe': rng.choice(['cpe:/a:redhat:openshift:4.16::el9',
                                                  'cpe:/a:redhat:openshift:4.12::el8', '']),
                  'version': rng.choice(['v4.16.0', 'v4.12.0', '.']),
                  'release': rng.choice(['202404030309.p0', '1781813947', '1500000000'])}
    elif shape == 'ocp_registry':
        ref = f"registry.redhat.io/{rng.choice(['openshift4/ose-cli-rhel9', 'openshift4/ose-cli'])}@sha256:{sha}"
    elif shape == 'operator':
        ref = f"registry.redhat.io/{rng.choice(['rhoai/odh-model-controller-rhel9', 'web-terminal/web-terminal-tooling-rhel9', 'rhacm2/console-rhel9'])}@sha256:{sha}"
    else:
        ref = f"registry.redhat.io/rhoai/odh-model-controller-rhel9@sha256:{sha}"
        labels = {'name': rng.choice(['managed-open-data-hub/odh-model-controller-rhel9',
                                      'web-terminal/web-terminal-tooling-rhel9']),
                  'cpe': rng.choice(['cpe:/a:redhat:openshift_ai:2.16::el9', '',
                                     'cpe:/a:redhat:openshift:4.16::el9']),
                  'version': '2.16.0', 'release': '1781813947'}
    os_hint = rng.choice(['', '', 'rhel:9', 'rhel:8', 'Red Hat Enterprise Linux 9'])
    if labels:
        ctx = mod.parse_context_from_labels(labels, ref, os_hint=os_hint)
    else:
        ctx = mod.parse_image_ref(ref, os_hint=os_hint)
    if rng.random() < 0.3:
        ctx.extra_digests = [f"sha256:{rng.choice(SHAS)}"]
    if rng.random() < 0.3:
        ctx.sbom_src_map = {'libsmartcols': 'util-linux', 'perl-libs': 'perl',
                            'golang.org/x/net': 'buildah', 'python3-chardet': 'python-chardet'}
    if rng.random() < 0.3:
        ctx.sbom_packages = {'openssl-libs': ['1:3.0.7-28.el9_4'], 'curl': ['7.76.1-40.el9'],
                             'util-linux': ['2.37.4-21.el9']}
    if rng.random() < 0.15:
        ctx.ocp_component = rng.choice(['etcd', 'cli', 'rhel-coreos'])
    return ctx


def rrow(rng):
    kind = rng.choices(['rpm', 'go', 'java', 'img', 'misc'], [60, 18, 6, 10, 6])[0]
    row = {'CVE': 'CVE-2099-0001', 'SEVERITY': rng.choice(['HIGH', 'MODERATE_VULNERABILITY_SEVERITY', 'LOW', '']),
           'FIXED_VERSION': rng.choice(['', '', '1.2.3'])}
    if kind == 'rpm':
        name = rng.choice(RPM_NAMES)
        ep = rng.choice(['', '', '1:', '32:'])
        ver = rversion(rng)
        if SEEN_RPMS and rng.random() < 0.7:
            # aim at a package the document names: same / older / newer
            # release, or the same upstream on another minor stream
            name, vr, dep = rng.choice(SEEN_RPMS)
            up, _, rel = vr.partition('-')
            head, _, dist = rel.partition('.')
            r = rng.random()
            if r < 0.25:
                ver = vr
            elif r < 0.45 and head.isdigit():
                ver = f"{up}-{int(head) + rng.choice([-1, 1, 5])}.{dist}"
            elif r < 0.65:
                ver = f"{up}-{head}.{rng.choice(DIST[:10])}"
            elif r < 0.8:
                ver = f"{rng.choice(['0.1', '9.9', up + '.1'])}-{head}.{dist}"
            ep = rng.choice(['', f'{dep}:']) if dep != '0' else rng.choice(['', '', '0:'])
        row.update(COMPONENT=name, VERSION=ep + ver, SOURCE='OS',
                   LOCATION='var/lib/rpm')
        if rng.random() < 0.4:
            row['SRPM'] = rng.choice([name, 'util-linux', 'python-chardet', 'perl', '', 'nan'])
    elif kind == 'go':
        row.update(COMPONENT=rng.choice(GO_COMPS), VERSION=rng.choice(['v0.1.0', 'v1.2.3']),
                   SOURCE='GO', LOCATION='usr/bin/oc')
    elif kind == 'java':
        row.update(COMPONENT=rng.choice(JAVA), VERSION='2.13.4.redhat-00001', SOURCE='JAVA')
    elif kind == 'img':
        row.update(COMPONENT=rng.choice(IMAGES), VERSION=rng.choice(['1781813947', '1.16.5-2']),
                   SOURCE='OS')
    else:
        row.update(COMPONENT=rng.choice(['tar', 'jackson-databind', 'rhcos']),
                   VERSION=rng.choice(['1.0', '', '4.16.0']),
                   SOURCE=rng.choice(['OS', 'PYTHON', 'IMAGE']))
    return row


def norm(vals):
    return [str(v) for v in vals]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--docs', type=int, default=1500)
    ap.add_argument('--rows', type=int, default=30)
    ap.add_argument('--seed', type=int, default=1)
    ap.add_argument('--show', type=int, default=8)
    ap.add_argument('--coverage', action='store_true', help='print legacy decision kinds hit')
    args = ap.parse_args()

    kinds = collections.Counter()
    _orig_eval = old._evaluate

    def _spy(row, ctx, data, maps):
        out = _orig_eval(row, ctx, data, maps)
        kinds[out[3].get('kind', '') + ('/unstated' if out[3].get('unstated') else '')] += 1
        return out
    old._evaluate = _spy

    rng = random.Random(args.seed)
    total = diffs = 0
    shown = 0
    verdicts = collections.Counter()
    for d in range(args.docs):
        SEEN_RPMS.clear()
        doc = rdoc(rng)
        wl_seed = rng.random()
        rows = [rrow(rng) for _ in range(args.rows)]
        doc_old, doc_new = copy.deepcopy(doc), copy.deepcopy(doc)
        ctx_old = rworkload(random.Random(wl_seed), old)
        ctx_new = rworkload(random.Random(wl_seed), new)
        for row in rows:
            total += 1
            try:
                a = norm(old.audit_row_with_doc(dict(row), ctx_old, doc_old))
                a.append(old._vex_product_with_doc(dict(row), ctx_old, doc_old))
            except Exception as exc:          # legacy crash: record, still compare
                a = ['EXC', type(exc).__name__]
            try:
                b = norm(new.audit_row_with_doc(dict(row), ctx_new, doc_new))
                b.append(new._vex_product_with_doc(dict(row), ctx_new, doc_new))
            except Exception as exc:
                b = ['EXC', type(exc).__name__, str(exc)[:200]]
            verdicts[a[0]] += 1
            if a[:2] == ['EXC'] * 1 + a[1:2] and b[:2] == a[:2]:
                continue
            if a != b:
                diffs += 1
                if shown < args.show:
                    shown += 1
                    print(f'--- doc {d} ctx={ctx_old.workload_type}/{ctx_old.image_ref} '
                          f'rhel={ctx_old.rhel_ver} ocp={ctx_old.ocp_ver}')
                    print('    row', row)
                    for i, (x, y) in enumerate(zip(a, b)):
                        if x != y:
                            print(f'    [{i}] old={x!r}\n        new={y!r}')
                    if len(a) != len(b):
                        print('    old', a, '\n    new', b)
    if args.coverage:
        for k, n in sorted(kinds.items(), key=lambda t: -t[1]):
            print(f'  {n:7d}  {k}')
    print(f'\n{total} rows, {diffs} differences   verdicts={dict(verdicts)}')
    sys.exit(1 if diffs else 0)


if __name__ == '__main__':
    main()
