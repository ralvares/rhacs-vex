"""Synthetic Red Hat CSAF-VEX documents, built into a real index, judged by the engine."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from vextriage.engine import Engine, resolve  # noqa: E402
from vextriage.index import Index  # noqa: E402
from vextriage.model import Finding, Image, Package  # noqa: E402

PRODUCTS = {
    'red_hat_products': ('All currently supported Red Hat products', 'cpe:/a:redhat'),
    'red_hat_enterprise_linux_9': ('Red Hat Enterprise Linux 9', 'cpe:/o:redhat:enterprise_linux:9'),
    'red_hat_enterprise_linux_8': ('Red Hat Enterprise Linux 8', 'cpe:/o:redhat:enterprise_linux:8'),
    'BaseOS-9.0.0.Z.E4S': ('Red Hat Enterprise Linux BaseOS E4S (v.9.0)', 'cpe:/a:redhat:rhel_e4s:9.0::baseos'),
    'BaseOS-9.2.0.Z.MAIN': ('Red Hat Enterprise Linux BaseOS (v. 9)', 'cpe:/o:redhat:enterprise_linux:9::baseos'),
    'BaseOS-9.2.0.Z.EUS': ('Red Hat Enterprise Linux BaseOS EUS (v.9.2)', 'cpe:/a:redhat:rhel_eus:9.2::baseos'),
    'BaseOS-9.4.0.Z.EUS': ('Red Hat Enterprise Linux BaseOS EUS (v.9.4)', 'cpe:/a:redhat:rhel_eus:9.4::baseos'),
    'BaseOS-9.6.0.Z.MAIN.EUS': ('Red Hat Enterprise Linux BaseOS (v. 9)', 'cpe:/o:redhat:enterprise_linux:9::baseos'),
    'BaseOS-9.8.0.Z.MAIN.EUS': ('Red Hat Enterprise Linux BaseOS (v. 9)', 'cpe:/o:redhat:enterprise_linux:9::baseos'),
    'AppStream-8.10.0.Z.MAIN.EUS': ('Red Hat Enterprise Linux AppStream (v. 8)',
                                    'cpe:/a:redhat:enterprise_linux:8::appstream'),
    'red_hat_openshift_container_platform_4': ('Red Hat OpenShift Container Platform 4', 'cpe:/a:redhat:openshift:4'),
    'Red Hat OpenShift Container Platform 4.19': ('Red Hat OpenShift Container Platform 4.19',
                                                  'cpe:/a:redhat:openshift:4.19::el9'),
    'Red Hat OpenShift Container Platform 4.20': ('Red Hat OpenShift Container Platform 4.20',
                                                  'cpe:/a:redhat:openshift:4.20::el9'),
    'Red Hat OpenShift Container Platform 4.21': ('Red Hat OpenShift Container Platform 4.21',
                                                  'cpe:/a:redhat:openshift:4.21::el9'),
    '9Base-RHOSE-4.18': ('Red Hat OpenShift Container Platform 4.18', 'cpe:/a:redhat:openshift:4.18::el9'),
    'red_hat_openshift_gitops': ('Red Hat OpenShift GitOps', 'cpe:/a:redhat:openshift_gitops:1'),
    'Red Hat OpenShift GitOps 1.18': ('Red Hat OpenShift GitOps 1.18', 'cpe:/a:redhat:openshift_gitops:1.18::el8'),
    'Red Hat OpenShift GitOps 1.4': ('Red Hat OpenShift GitOps 1.4', 'cpe:/a:redhat:openshift_gitops:1.4::el8'),
    'Red Hat Hardened Images': ('Red Hat Hardened Images', 'cpe:/a:redhat:hummingbird:1'),
}


def rpm(name, vr='', arch='x86_64', epoch=None, mod=''):
    q = [f'arch={arch}'] if arch else []
    if epoch:
        q.append(f'epoch={epoch}')
    if mod:
        q.append(f'rpmmod={mod}')
    pid = f'{name}-{epoch or 0}:{vr}.{arch}' if vr else name
    return pid, f'pkg:rpm/redhat/{name}' + (f'@{vr}' if vr else '') + ('?' + '&'.join(q) if q else '')


def oci(path, digest='', tag='', arch='amd64'):
    name = path.rsplit('/', 1)[-1]
    ns = path.rsplit('/', 1)[0]
    if digest:
        pid = f'registry.redhat.io/{path}@sha256:{digest}_{arch}'
        purl = f'pkg:oci/{name}@sha256%3A{digest}?arch={arch}&repository_url=registry.redhat.io/{ns}&tag={tag}'
    else:
        pid = path
        purl = f'pkg:oci/{name}?repository_url=registry.redhat.io/{path}'
    return pid, purl


def csaf(cve, statements, title='test'):
    """statements: (status, product id, (component pid, purl) | None, flag, remedy, severity)"""
    nodes, rels, status, flags, rems, threats = {}, [], {}, [], [], []
    for st in statements:
        st = tuple(st) + (None,) * (6 - len(st))
        s, parent, comp, flag, remedy, sev = st
        name, cpe = PRODUCTS[parent]
        nodes[parent] = {'product_id': parent, 'name': name, 'product_identification_helper': {'cpe': cpe}}
        if comp:
            cpid, purl = comp
            nodes[cpid] = {'product_id': cpid, 'name': cpid, 'product_identification_helper': {'purl': purl}}
            full = f'{parent}:{cpid}'
            rels.append({'category': 'default_component_of', 'full_product_name': {'product_id': full},
                         'product_reference': cpid, 'relates_to_product_reference': parent})
        else:
            full = parent
        status.setdefault(s, []).append(full)
        if flag:
            flags.append({'label': flag, 'product_ids': [full]})
        for r in (remedy or []):
            rems.append({'category': r[0], 'details': r[1], 'product_ids': [full]})
        threats.append({'category': 'impact', 'details': sev or 'Moderate', 'product_ids': [full]})
    return {'document': {'title': title, 'aggregate_severity': {'text': 'Moderate'}},
            'product_tree': {'branches': [{'product': n} for n in nodes.values()], 'relationships': rels},
            'vulnerabilities': [{'cve': cve, 'product_status': status, 'flags': flags, 'remediations': rems,
                                 'threats': threats}]}


@pytest.fixture
def index(tmp_path):
    """index(docs) → a real Index built from the given CSAF documents."""
    def build(*docs):
        vex = tmp_path / 'vex'
        vex.mkdir(exist_ok=True)
        for d in docs:
            cve = d['vulnerabilities'][0]['cve']
            (vex / f'{cve}.json').write_text(json.dumps(d))
        ix = Index(str(tmp_path / 'index.sqlite'))
        ix.update(str(vex), workers=1)
        return ix
    return build


def rhel_image(major=9, minor=4, repo='ubi9/ubi', labels=None, registry='registry.access.redhat.com',
               digests=()):
    return Image(ref=f'{registry}/{repo}', registry=registry, repo=repo, labels=labels or {},
                 digests=set(digests), os_id='rhel', rhel_major=major, rhel_minor=minor)


def rpm_pkg(name, vr, source=None, epoch=None, module='', vendor='Red Hat, Inc.'):
    return Package('rpm', name, vr, purl=f'pkg:rpm/redhat/{name}@{vr}?arch=x86_64', epoch=epoch,
                   arch='x86_64', source=source or name, module=module, vendor=vendor)


def judge(ix, image, pkg, cve='CVE-2099-0001'):
    if pkg not in image.packages:
        image.packages.append(pkg)
    eng = Engine(ix, resolve(image, ix))
    return eng.judge(Finding(cve, pkg))
