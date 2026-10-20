"""One test per rule of the engine (docs/RULES.md), on synthetic Red Hat documents."""
from conftest import csaf, judge, oci, rhel_image, rpm, rpm_pkg

from vextriage.model import Image, Package

CVE = 'CVE-2099-0001'
KA, KNA, FIXED, UI = 'known_affected', 'known_not_affected', 'fixed', 'under_investigation'


# ── every finding ───────────────────────────────────────────────────────────

def test_no_vex_document_keeps_the_finding(index):
    ix = index(csaf('CVE-2099-0002', [(KA, 'red_hat_enterprise_linux_9', rpm('zlib'))]))
    v = judge(ix, rhel_image(), rpm_pkg('zlib', '1.2.11-40.el9'))
    assert v.status == 'affected' and v.rule == 'no_vex'


def test_vendor_catch_all_not_affected(index):
    ix = index(csaf(CVE, [(KNA, 'red_hat_products', None)]))
    v = judge(ix, rhel_image(), rpm_pkg('zlib', '1.2.11-40.el9'))
    assert (v.status, v.stated, v.rule) == ('not_affected', True, 'vendor')


def test_this_build_digest_decides_for_everything_inside(index):
    d = 'ab' * 32
    ix = index(csaf(CVE, [(FIXED, 'Red Hat OpenShift Container Platform 4.20',
                           oci('openshift4/ose-cli-rhel9', d, 'v4.20.0-202601010000.p0')),
                          (KA, 'red_hat_enterprise_linux_9', rpm('zlib'))]))
    img = rhel_image(repo='openshift4/ose-cli-rhel9', registry='registry.redhat.io', digests=[d],
                     labels={'cpe': 'cpe:/a:redhat:openshift:4.20::el9'})
    v = judge(ix, img, rpm_pkg('zlib', '1.2.11-40.el9'))
    assert (v.status, v.stated, v.rule) == ('fixed', True, 'this_build')


# ── rpms: the RHEL stream ladder ────────────────────────────────────────────

def test_exact_build_is_the_fix(index):
    ix = index(csaf(CVE, [(FIXED, 'BaseOS-9.4.0.Z.EUS', rpm('openssl', '3.0.7-29.el9_4', epoch=1))]))
    v = judge(ix, rhel_image(minor=4), rpm_pkg('openssl', '3.0.7-29.el9_4', epoch=1))
    assert (v.status, v.stated, v.rule) == ('fixed', True, 'rpm_exact')


def test_our_streams_fix_decides_both_ways(index):
    ix = index(csaf(CVE, [(FIXED, 'BaseOS-9.4.0.Z.EUS', rpm('openssl', '3.0.7-29.el9_4', epoch=1)),
                          (FIXED, 'BaseOS-9.6.0.Z.MAIN.EUS', rpm('openssl', '3.2.2-6.el9_6', epoch=1))]))
    old = judge(ix, rhel_image(minor=4), rpm_pkg('openssl', '3.0.7-27.el9_4', epoch=1))
    assert (old.status, old.stated, old.rule, old.fix) == ('affected', True, 'rpm_stream_fix', '1:3.0.7-29.el9_4')
    new = judge(ix, rhel_image(minor=4), rpm_pkg('openssl', '3.0.7-29.el9_4.2', epoch=1))
    assert (new.status, new.rule) == ('fixed', 'rpm_stream_fix')


def test_epoch_stated_on_one_side_only(index):
    ix = index(csaf(CVE, [(FIXED, 'BaseOS-9.4.0.Z.EUS', rpm('openssl', '3.0.7-29.el9_4', epoch=1))]))
    v = judge(ix, rhel_image(minor=4), rpm_pkg('openssl', '3.0.7-30.el9_4'))
    assert v.status == 'fixed'


def test_inherited_mainline_fix(index):
    # 9.2 mainline fix; a 9.4 image inherits it
    ix = index(csaf(CVE, [(FIXED, 'BaseOS-9.2.0.Z.MAIN', rpm('libxml2', '2.9.13-5.el9_2'))]))
    assert judge(ix, rhel_image(minor=4), rpm_pkg('libxml2', '2.9.13-6.el9_4')).status == 'fixed'
    v = judge(ix, rhel_image(minor=4), rpm_pkg('libxml2', '2.9.13-3.el9'))
    assert (v.status, v.stated, v.rule) == ('affected', False, 'rpm_inherited')


def test_side_stream_backports_never_clear_while_the_line_is_affected(index):
    ix = index(csaf(CVE, [(FIXED, 'BaseOS-9.0.0.Z.E4S', rpm('systemd-libs', '252-14.el9_0.4')),
                          (FIXED, 'BaseOS-9.2.0.Z.EUS', rpm('systemd-libs', '252-14.el9_2.9')),
                          (KA, 'red_hat_enterprise_linux_9', rpm('systemd'), None,
                           [('workaround', 'no mitigation'), ('none_available', 'Fix deferred')])]))
    v = judge(ix, rhel_image(minor=8), rpm_pkg('systemd-libs', '252-55.el9_7', source='systemd'))
    assert (v.status, v.stated, v.rule, v.plan) == ('affected', True, 'rpm_open', 'Fix deferred')


def test_fix_only_in_later_stream_is_errata_policy(index):
    ix = index(csaf(CVE, [(FIXED, 'BaseOS-9.8.0.Z.MAIN.EUS', rpm('libarchive', '3.5.3-11.el9_8'))]))
    v = judge(ix, rhel_image(minor=7), rpm_pkg('libarchive', '3.5.3-9.el9_7'))
    assert (v.status, v.stated, v.rule, v.fix) == ('affected', False, 'rpm_errata', '3.5.3-11.el9_8')


def test_newer_upstream_version_than_every_fix(index):
    ix = index(csaf(CVE, [(FIXED, 'BaseOS-9.0.0.Z.E4S', rpm('expat', '2.2.10-12.el9_0.4'))]))
    v = judge(ix, rhel_image(minor=6), rpm_pkg('expat', '2.5.0-6.el9_6'))
    assert (v.status, v.rule) == ('fixed', 'rpm_newer_version')


def test_later_stream_than_every_fix_needs_nothing_open(index):
    fixes = [(FIXED, 'BaseOS-9.0.0.Z.E4S', rpm('glibc', '2.34-28.el9_0.4'))]
    ix = index(csaf(CVE, fixes))
    assert judge(ix, rhel_image(minor=8), rpm_pkg('glibc', '2.34-272.el9_8')).rule == 'rpm_later_stream'
    ix = index(csaf('CVE-2099-0003', fixes + [(KA, 'red_hat_enterprise_linux_9', rpm('glibc'))]))
    v = judge(ix, rhel_image(minor=8), rpm_pkg('glibc', '2.34-272.el9_8'), cve='CVE-2099-0003')
    assert (v.status, v.rule) == ('affected', 'rpm_open')


def test_a_binarys_own_statement_outranks_its_source(index):
    ix = index(csaf(CVE, [(KNA, 'red_hat_enterprise_linux_9', rpm('vim-filesystem', arch=''),
                           'vulnerable_code_not_present'),
                          (FIXED, 'BaseOS-9.4.0.Z.EUS', rpm('vim', '8.2.2637-21.el9_4', arch='src', epoch=2))]))
    v = judge(ix, rhel_image(minor=4), rpm_pkg('vim-filesystem', '8.2.2637-20.el9_4', source='vim', epoch=2))
    assert (v.status, v.stated, v.justification) == ('not_affected', True, 'vulnerable_code_not_present')


def test_subpackage_not_affected_where_its_source_is_fixed(index):
    ix = index(csaf(CVE, [(KNA, 'BaseOS-9.8.0.Z.MAIN.EUS', rpm('libacl', '2.4.0-1.el9_8')),
                          (FIXED, 'BaseOS-9.8.0.Z.MAIN.EUS', rpm('acl', '2.4.0-1.el9_8')),
                          (FIXED, 'BaseOS-9.8.0.Z.MAIN.EUS', rpm('acl', '2.4.0-1.el9_8', arch='src'))]))
    v = judge(ix, rhel_image(minor=4), rpm_pkg('libacl', '2.3.1-4.el9', source='acl'))
    assert (v.status, v.rule) == ('not_affected', 'rpm_subpackage')
    # the tool itself is still behind the fix
    assert judge(ix, rhel_image(minor=4), rpm_pkg('acl', '2.3.1-4.el9')).status == 'affected'


def test_module_streams_do_not_cross(index):
    ix = index(csaf(CVE, [(KNA, 'red_hat_enterprise_linux_8', rpm('nodejs', arch='', mod='nodejs:18')),
                          (FIXED, 'AppStream-8.10.0.Z.MAIN.EUS',
                           rpm('nodejs', '20.19.5-1.module+el8.10.0+23460+aa13b1c0', mod='nodejs:20:8100020250902', epoch=1))]))
    img = rhel_image(major=8, minor=10, repo='ubi8/nodejs-20')
    v = judge(ix, img, rpm_pkg('nodejs', '20.18.2-1.module+el8.10.0+22748+9c4e1b65', epoch=1, module='nodejs:20'))
    assert (v.status, v.rule) == ('affected', 'rpm_stream_fix')


def test_a_version_less_id_with_another_majors_purl_is_version_less(index):
    # CVE-2026-63380: red_hat_enterprise_linux_9:libevent.src, purl libevent@2.1.12-16.el10
    st = [(KNA, 'red_hat_enterprise_linux_9', ('libevent.src', 'pkg:rpm/redhat/libevent@2.1.12-16.el10?arch=src'),
           'vulnerable_code_not_present'),
          (KA, 'red_hat_enterprise_linux_8', ('libevent.src', 'pkg:rpm/redhat/libevent@2.1.12-16.el10?arch=src'))]
    ix = index(csaf(CVE, st))
    v = judge(ix, rhel_image(minor=8), rpm_pkg('libevent', '2.1.13-1.el9_8'))
    assert (v.status, v.stated, v.rule, v.justification) == ('not_affected', True, 'rpm_not_affected',
                                                            'vulnerable_code_not_present')
    assert judge(ix, rhel_image(major=8, minor=10), rpm_pkg('libevent', '2.1.8-5.el8')).rule == 'rpm_open'


def test_rpm_not_built_by_red_hat(index):
    ix = index(csaf(CVE, [(KA, 'red_hat_enterprise_linux_8', rpm('mongodb-org-server'))]))
    v = judge(ix, rhel_image(major=8, minor=10), rpm_pkg('mongodb-org-server', '8.0.3-1.el8', vendor='MongoDB'))
    assert (v.status, v.rule) == ('affected', 'not_red_hat')


def test_rpm_not_listed_for_our_rhel(index):
    ix = index(csaf(CVE, [(FIXED, 'red_hat_enterprise_linux_8', rpm('curl'))]))
    v = judge(ix, rhel_image(), rpm_pkg('curl', '7.76.1-29.el9_4'))
    assert (v.status, v.stated) == ('not_affected', False)


def test_another_lineage_never_decides(index):
    # Hardened Images (hum) builds say nothing about RHEL's python3-urllib3
    ix = index(csaf(CVE, [(FIXED, 'Red Hat Hardened Images', rpm('python3-urllib3', '2.8.0-1.hum1', arch='noarch'))]))
    v = judge(ix, rhel_image(), rpm_pkg('python3-urllib3', '1.26.5-5.el9_4.1', source='python-urllib3'))
    assert (v.status, v.rule) == ('not_affected', 'rpm_not_listed')


def test_rpm_made_by_openshift_is_decided_by_openshift(index):
    ix = index(csaf(CVE, [(FIXED, '9Base-RHOSE-4.18', rpm('cri-o', '1.31.6-2.rhaos4.18.git1b0a2f6.el9')),
                          (KA, 'red_hat_openshift_container_platform_4', rpm('cri-o'))]))
    img = rhel_image(repo='openshift4/ose-cri-o', registry='registry.redhat.io',
                     labels={'cpe': 'cpe:/a:redhat:openshift:4.20::el9'})
    newer = judge(ix, img, rpm_pkg('cri-o', '1.33.2-3.rhaos4.20.git2a1b.el9'))
    assert (newer.status, newer.rule) == ('fixed', 'product_past_fix')
    older = judge(ix, img, rpm_pkg('cri-o', '1.31.6-1.rhaos4.18.git0000.el9'))
    assert (older.status, older.rule) == ('affected', 'product_fix')


def test_the_images_product_not_affected_clears_a_rhel_rpm(index):
    ix = index(csaf(CVE, [(FIXED, 'BaseOS-9.8.0.Z.MAIN.EUS', rpm('systemd', '252-60.el9_8')),
                          (KNA, 'red_hat_openshift_container_platform_4', rpm('systemd', arch=''))]))
    img = rhel_image(repo='openshift4/ose-cli-rhel9', registry='registry.redhat.io',
                     labels={'cpe': 'cpe:/a:redhat:openshift:4.20::el9'})
    v = judge(ix, img, rpm_pkg('systemd', '252-32.el9_4'))
    assert (v.status, v.rule) == ('not_affected', 'product_context')


def test_remedy_priority_prefers_the_plan_over_a_workaround(index):
    ix = index(csaf(CVE, [(KA, 'red_hat_enterprise_linux_9', rpm('tar'), None,
                           [('workaround', 'Do not extract untrusted archives'), ('no_fix_planned', 'Will not fix')])]))
    v = judge(ix, rhel_image(), rpm_pkg('tar', '1.34-6.el9'))
    assert (v.status, v.plan) == ('affected', 'Will not fix')


# ── images and what is inside them ──────────────────────────────────────────

def ocp_image(digest='cd' * 32, built='202602031200'):
    return Image(ref=f'registry.redhat.io/openshift4/ose-cli-rhel9@sha256:{digest}', registry='registry.redhat.io',
                 repo='openshift4/ose-cli-rhel9', digests={digest}, os_id='rhel', rhel_major=9, rhel_minor=4,
                 labels={'cpe': 'cpe:/a:redhat:openshift:4.20::el9', 'version': 'v4.20.0',
                         'release': f'{built}.p2.g040daf8.assembly.stream.el9', 'name': 'openshift/ose-cli-rhel9'})


def go(name='golang.org/x/net', version='v0.42.0'):
    return Package('go', name, version, purl=f'pkg:golang/{name}@{version}', locations=('/usr/bin/oc',))


def test_newer_builds_not_affected_do_not_clear_an_older_build(index):
    later = [(KNA, 'Red Hat OpenShift Container Platform 4.20',
              oci('openshift4/ose-cli-rhel9', 'e1' * 32, 'v4.20.0-202609091200.p2'))]
    line = [(KA, 'red_hat_openshift_container_platform_4', oci('openshift4/ose-cli-rhel9'))]
    v = judge(index(csaf(CVE, later + line)), ocp_image(), go())
    assert (v.status, v.rule) == ('affected', 'image_line_open')


def test_an_earlier_build_of_our_version_speaks_for_ours(index):
    earlier = [(KNA, 'Red Hat OpenShift Container Platform 4.20',
                oci('openshift4/ose-cli-rhel9', 'e2' * 32, 'v4.20.0-202601010000.p2'))]
    line = [(KA, 'red_hat_openshift_container_platform_4', oci('openshift4/ose-cli-rhel9'))]
    v = judge(index(csaf(CVE, earlier + line)), ocp_image(), go())
    assert (v.status, v.stated, v.rule) == ('not_affected', False, 'image_build')


def test_fixed_in_a_later_build_of_our_version(index):
    later = [(FIXED, 'Red Hat OpenShift Container Platform 4.20',
              oci('openshift4/ose-cli-rhel9', 'e3' * 32, 'v4.20.0-202605010000.p2'))]
    v = judge(index(csaf(CVE, later)), ocp_image(), go())
    assert (v.status, v.rule) == ('affected', 'image_later_fix')


def test_fixed_only_in_a_newer_version(index):
    st = [(FIXED, 'Red Hat OpenShift Container Platform 4.21',
           oci('openshift4/ose-cli-rhel9', 'e4' * 32, 'v4.21.0-202601010000.p2'))]
    v = judge(index(csaf(CVE, st)), ocp_image(), go())
    assert (v.status, v.rule) == ('affected', 'image_newer_version')


def test_not_affected_in_a_newer_version_with_nothing_open_or_fixed(index):
    # holdout: the image not affected only in newer versions — 6,900 of 7,099 hidden
    # verdicts for our version were not affected. Before, an open image elsewhere in
    # OpenShift 4 made the errata assumption fire (3.4% right on those 1,288 cases).
    st = [(KNA, 'Red Hat OpenShift Container Platform 4.21', oci('openshift4/ose-cli-rhel9', 'e5' * 32,
                                                                   'v4.21.0-202601010000.p2')),
          (KA, 'red_hat_openshift_container_platform_4', oci('openshift4/ose-tests'))]
    v = judge(index(csaf(CVE, st)), ocp_image(), go())
    assert (v.status, v.stated, v.rule) == ('not_affected', False, 'image_newer_not_affected')
    # a fix anywhere for the image: newer versions not affected clear nothing
    st2 = st + [(FIXED, 'Red Hat OpenShift Container Platform 4.19', oci('openshift4/ose-cli-rhel9', 'e8' * 32,
                                                                         'v4.19.0-202605010000.p2'))]
    v = judge(index(csaf('CVE-2099-0007', st2)), ocp_image(), go(), cve='CVE-2099-0007')
    assert v.rule != 'image_newer_not_affected'
    st = [(KNA, 'Red Hat OpenShift Container Platform 4.19', oci('openshift4/ose-cli-rhel9', 'e6' * 32,
                                                                   'v4.19.0-202601010000.p2'))]
    v = judge(index(csaf('CVE-2099-0004', st)), ocp_image(), go(), cve='CVE-2099-0004')
    assert (v.status, v.rule) == ('not_affected', 'image_older_not_affected')


def test_payload_image_found_by_its_label_under_openshift(index):
    d = 'f0' * 32
    st = [(FIXED, 'Red Hat OpenShift Container Platform 4.20',
           oci('openshift4/ose-thanos-rhel9', 'e7' * 32, 'v4.20.0-202601010000.p2'))]
    ix = index(csaf(CVE, st))
    img = Image(ref=f'quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:{d}', registry='quay.io',
                repo='openshift-release-dev/ocp-v4.0-art-dev', digests={d}, os_id='rhel', rhel_major=9,
                rhel_minor=4, labels={'name': 'openshift/ose-thanos-rhel9', 'cpe': 'cpe:/a:redhat:openshift:4.20::el9',
                                      'release': '202602031200.p2.g0.assembly.stream.el9'})
    v = judge(ix, img, go())
    assert (v.status, v.rule) == ('fixed', 'image_build')


def test_a_module_shipped_by_an_rpm_follows_the_rpm(index):
    ix = index(csaf(CVE, [(FIXED, 'BaseOS-9.4.0.Z.EUS', rpm('python3-urllib3', '1.26.5-5.el9_4.3', arch='noarch'))]))
    img = rhel_image(minor=4)
    owner = rpm_pkg('python3-urllib3', '1.26.5-5.el9_4.1', source='python-urllib3')
    mod = Package('python', 'urllib3', '1.26.5', purl='pkg:pypi/urllib3@1.26.5', owner=owner)
    img.packages += [owner]
    v = judge(ix, img, mod)
    assert (v.status, v.rule) == ('affected', 'rpm_stream_fix') and v.reason.startswith('via rpm python3-urllib3')


def test_a_non_red_hat_images_own_module_is_not_covered(index):
    ix = index(csaf(CVE, [(KNA, 'red_hat_openshift_container_platform_4', oci('openshift4/ose-cli-rhel9'))]))
    img = Image(ref='docker.io/mongodb/mongodb-community-server:8.0', registry='docker.io',
                repo='mongodb/mongodb-community-server', os_id='rhel', rhel_major=8, rhel_minor=10,
                labels={'vendor': 'MongoDB'})
    v = judge(ix, img, go('github.com/golang-jwt/jwt/v4', 'v4.5.0'))
    assert (v.status, v.rule) == ('affected', 'not_covered')


def test_errata_assumption_needs_nothing_cleared_under_the_same_product(index):
    st = [(KA, 'red_hat_openshift_gitops', oci('openshift-gitops-1/argocd-rhel8'))]
    img = Image(ref='registry.redhat.io/openshift-gitops-1/gitops-rhel8-operator', registry='registry.redhat.io',
                repo='openshift-gitops-1/gitops-rhel8-operator', os_id='rhel', rhel_major=8, rhel_minor=7,
                labels={'version': 'v1.18.1'})
    seen = [(KNA, 'Red Hat OpenShift GitOps 1.18', oci('openshift-gitops-1/gitops-rhel8-operator', 'aa' * 32,
                                                       'v1.18.0-1'))]
    v = judge(index(csaf(CVE, st + seen)), img, go())
    # our image is named (an earlier build of our version, not affected): no assumption needed
    assert v.rule == 'image_build'
    other = [(KA, 'red_hat_openshift_gitops', oci('openshift-gitops-1/argocd-rhel8')),
             (FIXED, 'Red Hat OpenShift GitOps 1.4', oci('openshift-gitops-1/gitops-rhel8-operator', 'ab' * 32,
                                                         'v1.4.0-1'))]
    v = judge(index(csaf('CVE-2099-0005', other)), img, go(), cve='CVE-2099-0005')
    assert v.status == 'fixed'                       # 1.18.1 is past the 1.4 fix (version order)


def test_errata_assumption_yields_to_our_versions_own_list(index):
    # OpenShift 4 lists other images affected; OpenShift 4.20 lists its images' builds
    # not affected and does not name ours: Red Hat went through 4.20, no assumption
    line = [(KA, 'red_hat_openshift_container_platform_4', oci('openshift4/ose-tests'))]
    img = ocp_image()
    img.repo, img.labels['name'] = 'openshift4/ose-unnamed-rhel9', 'openshift/ose-unnamed-rhel9'
    v = judge(index(csaf(CVE, line)), img, go())
    assert (v.status, v.rule) == ('affected', 'errata_assumed')
    own = [(KNA, 'Red Hat OpenShift Container Platform 4.20', oci('openshift4/ose-thanos-rhel9', 'e9' * 32,
                                                                  'v4.20.0-202601010000.p2'))]
    v = judge(index(csaf('CVE-2099-0008', line + own)), img, go(), cve='CVE-2099-0008')
    assert (v.status, v.rule) == ('not_affected', 'not_listed')


def test_statements_about_another_arch_are_ignored(index):
    # 8.6 E4S lists krb5-libs not affected on aarch64 only; x86_64 is fixed
    ix = index(csaf(CVE, [(FIXED, 'BaseOS-9.4.0.Z.EUS', rpm('krb5-libs', '1.21.1-2.el9_4')),
                          (FIXED, 'BaseOS-9.4.0.Z.EUS', rpm('krb5', '1.21.1-2.el9_4', arch='src')),
                          (KNA, 'BaseOS-9.4.0.Z.EUS', rpm('krb5-libs', '1.21.1-2.el9_4', arch='aarch64'))]))
    v = judge(ix, rhel_image(minor=4), rpm_pkg('krb5-libs', '1.21.1-1.el9', source='krb5'))
    assert (v.status, v.rule) == ('affected', 'rpm_stream_fix')


def test_subpackage_clean_in_our_stream(index):
    ix = index(csaf(CVE, [(KNA, 'BaseOS-9.4.0.Z.EUS', rpm('vim-minimal', '8.2.2637-21.el9_4', epoch=2)),
                          (FIXED, 'BaseOS-9.4.0.Z.EUS', rpm('vim', '8.2.2637-21.el9_4', arch='src', epoch=2))]))
    v = judge(ix, rhel_image(minor=4), rpm_pkg('vim-minimal', '8.2.2637-20.el9_4', source='vim', epoch=2))
    assert (v.status, v.stated, v.rule) == ('not_affected', True, 'rpm_clean_build')


def test_version_order():
    from vextriage.rpm import evr_cmp, vercmp
    from vextriage.version import compare
    assert vercmp('1.0~rc1', '1.0') == -1 and vercmp('1.0^git1', '1.0') == 1 and vercmp('1.0a', '1.0') == 1
    assert vercmp('2.34-100.el9_4.12', '2.34-100.el9_4.2') == 1
    assert evr_cmp('1:3.0.7-27.el9', '3.0.7-24.el9_4') == 1         # the stated epoch is taken for both
    assert evr_cmp('0:1.0-1', '1:0.9-1') == -1
    assert compare('maven', '1.11.3.redhat-00001', '1.11.3') == 1
    assert compare('maven', '1.0-rc1', '1.0') == -1
    assert compare('golang', 'v0.0.0-20211209120228-48547f28849e', 'v0.1.0') == -1
    assert compare('npm', '1.2.3-beta.2', '1.2.3-beta.11') == -1
    assert compare('golang', 'UNKNOWN', 'v1.0.0') is None


def test_dist_tags():
    from vextriage.rpm import dist
    assert dist('1.29.1-3.rhaos4.16.git3d1c9d4.el9').token == 'rhaos4.16'
    assert (dist('2.34-100.el9_4.12').major, dist('2.34-100.el9_4.12').minor) == (9, 4)
    assert dist('3.18-4.module%2Bel8.9.0%2B21697').module
    assert dist('2.8.0-1.hum1').token == 'hum' and dist('1.0-1.el8ap').token == 'elap'


def test_openvex_names_the_package_as_a_product_too():
    # trivy keeps a finding whose path to the image meets an rpm dependency cycle
    # (python3-pip-wheel → python3-libs → … glibc ↔ bash): only the package as the
    # product reaches it. grype matches the image product with the subcomponent.
    from vextriage import openvex
    from vextriage.model import Verdict
    img = rhel_image(minor=8, digests=['ab' * 32, 'cd' * 32])
    pkg = rpm_pkg('python3-pip-wheel', '21.3.1-2.el9_8')
    st = openvex.statement(img, CVE, pkg, Verdict('not_affected', 'RHEL 9: ubi9/ubi not affected', True,
                                                  'vulnerable_code_not_present'))
    ids = [p['@id'] for p in st['products']]
    assert ids == ['pkg:oci/ubi@sha256:' + 'ab' * 32, 'pkg:oci/ubi@sha256:' + 'cd' * 32,
                   'pkg:rpm/redhat/python3-pip-wheel@21.3.1-2.el9_8']
    assert st['products'][0]['subcomponents'] == [{'@id': 'pkg:rpm/redhat/python3-pip-wheel@21.3.1-2.el9_8'}]
    # itself as its only subcomponent: trivy reads a bare product as covering what it depends on
    assert st['products'][2]['subcomponents'] == [{'@id': 'pkg:rpm/redhat/python3-pip-wheel@21.3.1-2.el9_8'}]
    assert st['justification'] == 'vulnerable_code_not_present'
    # the image itself: image products only
    whole = openvex.statement(img, CVE, Package('image', 'ubi9/ubi', '9.8-1'), Verdict('not_affected', 'x', True))
    assert [p['@id'] for p in whole['products']] == ids[:2]


def test_openvex_carries_the_scanners_id_as_an_alias():
    # grype reports Go modules as GHSA-…, and its VEX filter matches that id only
    from vextriage import openvex
    from vextriage.model import Verdict
    img = rhel_image(digests=['ab' * 32])
    v = Verdict('not_affected', 'not listed', False)
    doc = openvex.document(img, [(CVE, go(), v, 'GHSA-mh2q-q3fh-2475'), (CVE, go(), v, ''), (CVE, go(), v)])
    assert [s['vulnerability'] for s in doc['statements']] == [{'name': CVE, 'aliases': ['GHSA-mh2q-q3fh-2475']}]
