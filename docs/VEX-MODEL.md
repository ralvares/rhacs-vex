# VEX-MODEL.md — Red Hat CSAF-VEX Data Model (Ground-Truth Reference)

Design input for a clean rewrite of the RHACS↔VEX triage matching engine. Every count and
example below is **mined from the data**, not from memory. Reproduce with the scripts in
`analysis/` (each section names the script). Rules already validated in the working engine are
cited as **[triage.py:LINE]**; everything else is a fresh measurement over the corpus.

**Corpus measured:** `data/vex/CVE-*.json` = **7,212 files**, 0 parse errors (`analysis/mine_vex.py`).
(Task brief said 7,163; the on-disk count is 7,212 — reported as measured.) Scanner side sampled
from `data/scans/*.json` (13,745 files) and `data/sbom/*.sbom` (13,109 files) — see §7.

**Format:** CSAF 2.0, `document.category = "csaf_vex"`, publisher `Red Hat Product Security`,
engine `Red Hat SDEngine`. One file per CVE. Three top-level objects: `document`,
`product_tree` (`branches` + `relationships`), `vulnerabilities[]`.

**Counting conventions.** "refs" = occurrences of a product_id across all `product_status`
lists in all files (a PID appears once per arch, so refs ≈ per-arch statement count).
"files" for a status key = number of `vulnerabilities` entries where that key is non-empty
(denominator = 7,212). Distinct-parent counts dedupe the first `:`-segment.

---

## 1. The Product Universe

Mined by `analysis/mine_products.py`. **2,357 distinct parent products** (first PID segment),
**3,911,248 total parent refs**. Grouped into layers (refs = share of all statements):

| Layer | Distinct parents | Refs | Dominant CPE prefix |
|---|---:|---:|---|
| RHEL base repos | 1,414 | 2,695,900 | `cpe:/o:redhat:enterprise_linux`, `cpe:/a:redhat:enterprise_linux` |
| OpenShift versioned streams (`RHOSE`) | 63 | 670,427 | `cpe:/a:redhat:openshift:<v>::el<N>` |
| OpenShift + operators (human-named) | 166 | 341,210 | `cpe:/a:redhat:openshift`, `openshift_ai`, `service_mesh` |
| Other named products (middleware/standalone) | 529 | 109,990 | `cpe:/a:redhat:openjdk`, `quarkus`, `build_keycloak`, `jboss_fuse` |
| OpenShift version-neutral | 11 | 25,451 | `cpe:/a:redhat:openshift:<major>` |
| Ansible Automation Platform (RPM) | 10 | 20,438 | `cpe:/a:redhat:ansible_automation_platform` |
| JBoss / EAP / JWS / JBCS (middleware) | 79 | 20,314 | `cpe:/a:redhat:jboss_enterprise_application_platform` |
| Software Collections (RPM) | 1 | 9,856 | `cpe:/a:redhat:rhel_software_collections` |
| OpenStack (RPM) | 21 | 7,601 | `cpe:/a:redhat:openstack:<v>` |
| Ceph Storage (RPM) | 16 | 7,019 | `cpe:/a:redhat:ceph_storage:<v>` |
| Satellite (RPM) | 6 | 2,020 | `cpe:/a:redhat:satellite:6` |
| AMQ (broker/streams/clients) | 36 | 419 | `cpe:/a:redhat:amq_broker`, `amq_streams` |
| Fast Datapath (RPM) | 4 | 390 | `cpe:/o:redhat:enterprise_linux:<N>::fastdatapath` |
| Vendor catch-all `red_hat_products` | 1 | 213 | `cpe:/a:redhat` |

### 1a. RHEL base repos — naming grammar
Parent PID = `<Repo>-<Version><Stream>` OR the version-neutral `red_hat_enterprise_linux_<N>`.

- **Repo prefixes** (distinct-parent counts): `AppStream` 74, `BaseOS` 73, `CRB` 51,
  `HighAvailability` 38, `RT` 24, `NFV` 24, `ResilientStorage` 23, `Supplementary` 14.
  RT (Real Time) and NFV exist across RHEL 9→10 (e.g. `RT-9.3.0.GA`, `RT-10.0.Z.E2S`,
  `NFV-9.8.0.GA`). Older RHEL 5–7 use `NServer/NClient/NWorkstation`-style repos
  (`5Server-5.7.Z`, `7Server-optional-7.9.Z`, `7Server-RHSCL-3.8`).
- **GA vs z-stream/long-life suffixes** (distinct parents): `.Z` 167, `.GA` 89,
  `.Z.MAIN.EUS` 48, `.Z.EUS` 45, `.Z.MAIN` 41, `.Z.E4S` 35, `ELS` (in-name) 29,
  `.Z.TUS` 14, `.Z.E2S` 8, `.Z.AUS` 7.
- **Version-neutral RHEL:** `red_hat_enterprise_linux_{5..10}` with `cpe:/o:redhat:enterprise_linux:<N>`
  — 67,863 (RHEL8), 50,611 (RHEL9), 40,608 (RHEL7) refs. These are the whole-product nodes.
- Examples: `AppStream-8.10.0.Z.MAIN.EUS` (106,756 refs), `BaseOS-9.4.0.Z.EUS`,
  `CRB-8.6.0.Z.EUS`, `AppStream-9.8.0.Z.MAIN.EUS`, `red_hat_enterprise_linux_8`.

### 1b. RHEL long-life streams → PID suffix + CPE token
Each RHEL minor can appear under several parallel support streams; the suffix and CPE both encode it:

| Stream | PID suffix | CPE token | Example parent |
|---|---|---|---|
| GA (base) | `.GA` / plain `el<N>` | `cpe:/o:redhat:enterprise_linux:<N>` | `AppStream-8.6.0.GA` |
| z-stream | `.Z`, `.Z.MAIN` | `enterprise_linux` | `AppStream-9.5.0.Z.MAIN` |
| EUS (Extended Update Support) | `.Z.EUS` → `rhel_eus`; `.Z.MAIN.EUS` → OS CPE | `cpe:/a:redhat:rhel_eus:<v>` (verified 1,068×); `.Z.MAIN.EUS` uses `cpe:/o:redhat:enterprise_linux[_eus]` (1,033×) | `AppStream-9.4.0.Z.EUS` |
| E4S (Update Svcs for SAP) | `.Z.E4S` | `cpe:/a:redhat:rhel_e4s:<v>` | `AppStream-9.2.0.Z.E4S` |
| AUS (Advanced Update Support) | `.Z.AUS` | `cpe:/a:redhat:rhel_aus:<v>` | `AppStream-8.2.0.Z.AUS` |
| TUS (Telco Update Support) | `.Z.TUS` | `cpe:/a:redhat:rhel_tus:<v>` | `AppStream-8.4.0.Z.TUS` |
| ELS (Extended Lifecycle) | `-ELS` in name | `enterprise_linux` | `7Server-ELS` |
| E2S (RHEL 10 svc stream) | `.Z.E2S` | `enterprise_linux` | `AppStream-10.0.Z.E2S` |

### 1c. Layered RPM products (RPMs on top of RHEL, own dist-tag)
| Product | Parent PID shape | CPE | Dist-tag (§2) | 3 example parent PIDs |
|---|---|---|---|---|
| Fast Datapath | `fast_datapath_for_rhel_<N>` **and** `<N>Base-Fast-Datapath` **and** inside `RHOSE` streams | `cpe:/o:redhat:enterprise_linux:<N>::fastdatapath` | `el<N>fdp` | `fast_datapath_for_rhel_9`, `fast_datapath_for_rhel_8`, `9Base-Fast-Datapath` |
| Ceph Storage | `red_hat_ceph_storage_<N>`, `Red Hat Ceph Storage <N>`, `<N>Base-RHCEPH-<v>-Tools` | `cpe:/a:redhat:ceph_storage:<N>` | `el<N>cp` | `red_hat_ceph_storage_8`, `Red Hat Ceph Storage 8`, `9Base-RHCEPH-8.1-Tools` |
| Ansible AP | `Red Hat Ansible Automation Platform <v>`, `<N>Base-Ansible-Automation-Platform-<v>` | `cpe:/a:redhat:ansible_automation_platform` | `el<N>ap` | `9Base-Ansible-Automation-Platform-2.6`, `8Base-Ansible-Automation-Platform-2.5`, `red_hat_ansible_automation_platform_2` |
| OpenStack | `red_hat_openstack_platform_<v>`, `<N>Base-RHOS-<v>` | `cpe:/a:redhat:openstack:<v>` | `el<N>ost` | `red_hat_openstack_platform_17.1`, `red_hat_openstack_platform_16.2`, `8Base-RHOS-16.2` |
| Software Collections | `red_hat_software_collections` + `<N>Server-RHSCL-<v>` repos | `cpe:/a:redhat:rhel_software_collections` | `el<N>` (in SCL repo) | `red_hat_software_collections`, `7Server-RHSCL-3.8`, `7Workstation-RHSCL-3.8` |
| Satellite | `red_hat_satellite_6`, `<N>Base-satellite-<v>` | `cpe:/a:redhat:satellite:6` | `el<N>sat`, `el<N>pc` | `red_hat_satellite_6`, `8Base-satellite-6.16`, `9Base-satellite-6.16` |
| Advanced Virt | `<N>Base-Advanced-Virt-<v>` | `cpe:/a:redhat:advanced_virt` | `module+el8.x` | `8Base-Advanced-Virt-8.4.0.Z`, `8Base-Advanced-Virt-8.2.1`, `8Base-Advanced-Virt-CRB-8.2.1` |

### 1d. OpenShift core — versioned vs version-neutral (a critical distinction for scoping)
- **Versioned streams:** `<RHEL-base>Base-RHOSE-<ocp>` e.g. `8Base-RHOSE-4.14` (86,653 refs),
  `9Base-RHOSE-4.16`. CPE `cpe:/a:redhat:openshift:<ocp>::el<N>`. The `<N>Base` prefix pins the
  **RHEL** the OCP runs on; the `RHOSE-<ocp>` pins the **OCP** version.
- **Human-named per-version:** `Red Hat OpenShift Container Platform 4.19` (36,137 refs),
  `... 4.20` — same CPE family, name-based.
- **Version-neutral:** `red_hat_openshift_container_platform_4` (21,552 refs),
  `..._3.11`, `..._3.9`. CPE `cpe:/a:redhat:openshift:4` (no minor). These catch **all 4.x**
  and are admissible only as version-neutral related evidence **[triage.py:1711 `_is_version_neutral_product`]**.

### 1e. OpenShift layered & operator products (166 named + long tail)
Human-named per version, matched to workloads via OCI-purl namespace, not RHEL dist-tag. Examples:
`Red Hat OpenShift AI 2.25` (`openshift_ai`), `Red Hat Advanced Cluster Management … 2.15`
(`acm`), `multicluster engine for Kubernetes 2.8` (`multicluster_engine`),
`Red Hat OpenShift Data Foundation` (`odf`), `Red Hat OpenShift GitOps`, `Cluster Observability
Operator 1.5.0`, `Red Hat OpenShift Serverless`, `... Pipelines`, `Red Hat Quay` (`quay`),
`Red Hat Advanced Cluster Security 4` (`advanced_cluster_security`). CPE tokens seen:
`openshift_ai` 14, `service_mesh` 11, `ocp_tools` 11, `openshift_distributed_tracing` 10,
`openshift_builds` 10.

### 1f. Middleware / standalone
JBoss family (79 parents, `cpe:/a:redhat:jboss_enterprise_application_platform` 28,
`jboss_enterprise_web_server` 20, `jboss_core_services` 9; e.g.
`Red Hat JBoss Enterprise Application Platform`, `red_hat_jboss_core_services`,
`Red Hat JBoss Web Server 2.1`). AMQ (36 parents; `red_hat_amq_broker_7`, `red_hat_amq_clients`,
`Red Hat AMQ Streams 2.7.0`). Plus the "other named" bucket (529): `openjdk` (70), `quarkus` (38),
`build_keycloak` (30), `jboss_fuse` (17), `camel_quarkus` (15), Developer Hub, etc.

### 1g. Vendor catch-all
`red_hat_products` — single node, name "All currently supported Red Hat products",
`cpe:/a:redhat` (bare vendor CPE, no product token). 213 refs. Semantics in §5/§8.

---

## 2. Dist-tag → Product Decoder

The `.el<N>[_<minor>][suffix]` token in a NEVRA **release** field is the scoping key for RPM
findings. Mined by `analysis/mine_vex.py` (`dist_tags` + `dist_tag_parent_top`): counts are refs,
"top parents" shows which parent products carry the tag. **A dist-tag alone does not pin the
product** — the same `el9` appears under RHOSE, RHEL base, and layered products; the parent PID
disambiguates. Below, ranked by frequency.

| Dist-tag | Refs | Decodes to | Top-carrying parents (refs) |
|---|---:|---|---|
| `el9` | 770,997 | RHEL 9 GA (any el9 build) | `9Base-RHOSE-4.16` (60k), RHEL9 base, layered |
| `el8` | 485,527 | RHEL 8 GA | `8Base-RHOSE-4.14` (53k), RHEL8 base |
| `el9_4` | 166,693 | RHEL **9.4** minor stream | `AppStream-9.4.0.Z.EUS`, `BaseOS-9.4.0.Z.EUS`, `CRB-9.4.0.Z.EUS` |
| `el9_2` | 124,115 | RHEL 9.2 | `AppStream-9.2.0.Z.E4S`, `...9.2.0.Z.EUS` |
| `el8_6` | 117,480 | RHEL 8.6 | `AppStream-8.6.0.Z.EUS`, `CRB-8.6.0.Z.EUS` |
| `el9_6` | 107,486 | RHEL 9.6 | `AppStream-9.6.0.Z.EUS`, `...9.6.0.Z.MAIN.EUS` |
| `el8_10` | 104,078 | RHEL 8.10 | `BaseOS-8.10.0.Z.MAIN.EUS`, `AppStream-8.10.0.Z.MAIN.EUS` |
| `el9_0` | 103,817 | RHEL 9.0 | `AppStream-9.0.0.Z.E4S`, `...9.0.0.Z.EUS` |
| `el7` | 97,658 | RHEL 7 GA | `7Server-RHSCL-3.8`, `7Server-ELS` |
| `el10_0` | 81,922 | RHEL 10.0 | `AppStream-10.0.Z.E2S`, `BaseOS-10.0.Z.E2S` |
| `el7_9` | 78,194 | RHEL 7.9 | `7Server-7.9.Z`, `7Server-optional-7.9.Z` |
| `module+el8.4` | 74,929 | RHEL 8.4 **module-stream** build | `8Base-Advanced-Virt-8.4.0.Z`, `AppStream-8.4.0.Z.E4S` |
| `module+el8.6` | 73,141 | RHEL 8.6 module | `AppStream-8.6.0.GA`, `...8.6.0.Z.MAIN.EUS` |
| `el8_4` | 66,458 | RHEL 8.4 | `AppStream-8.4.0.Z.EUS/E4S/AUS` |
| `module+el8.10` | 64,355 | RHEL 8.10 module | `AppStream-8.10.0.Z.MAIN.EUS` |
| `el8_8`,`el8_2`,`el8_5`,`el9_5..9_8`,`el10_1/10_2` | — | corresponding RHEL minor | AppStream/BaseOS/CRB of that minor |
| `el9ap` | 53,686 | **Ansible AP** on RHEL 9 | `9Base-Ansible-Automation-Platform-2.6/2.5` |
| `el8ap` | 28,664 | Ansible AP on RHEL 8 | `8Base-Ansible-Automation-Platform-2.5` |
| `el8sat` / `el9sat` | 35,229 / 12,857 | **Satellite** on RHEL 8/9 | `8Base-satellite-6.16`, `9Base-satellite-6.16` |
| `el8pc` | 21,070 | Satellite **Capsule** | `8Base-satellite-6.16-capsule` |
| `el7sat` | 14,316 | Satellite on RHEL 7 | `7Server-satellite-6.11` |
| `el9fdp` / `el8fdp` | (subset) | **Fast Datapath** | `9Base-RHOSE-4.13`, `9Base-Fast-Datapath`, `8Base-RHOSE-4.11` |
| `el9cp` (`el8cp`) | (subset) | **Ceph** tools | `9Base-RHCEPH-7.1-Tools`, `...8.1-Tools` |
| `el8ost` / `el9ost` | (subset) | **OpenStack** | `8Base-RHOSE-4.13`, `8Base-RHOS-16.2` |
| `rhaos<ocp>.el<N>` | (in release) | **OCP** product build on RHEL N | e.g. `1.1.14-4.rhaos4.18.el9` |

Key reading rule: `el9_4` etc. = **minor-stream-specific** build → backport comparison must stay
within the same minor (§6). Bare `el9`/`el8` = GA (no minor) → compared against all streams.
`module+el8.<minor>` encodes minor as the 2nd component **[triage.py:1673 `_detect_rhel_minor`]**.

---

## 3. PID Grammar

A `product_id` in `product_status`/`threats`/`remediations`/`flags` is either a bare product-tree
node or a `relationship.full_product_name.product_id`. Shapes below mined by `analysis/mine_vex.py`
(`pid_shapes`), counts are refs over the whole corpus:

| Shape | Refs | Regex (component part after first `:`) | Example |
|---|---:|---|---|
| `nevra_arch` | 1,950,742 | `name-EPOCH:ver-rel.<arch>` | `4AS-LACD:java-1.4.2-ibm-0:1.4.2.13.11-1jpp.1.el4.i386` |
| `stream_imagepath_digest` | 590,336 | `<ns>/<img>@sha256:<hex>_<arch>` | `7Server-RH7-RHOSE-3.11:openshift3/apb-base@sha256:763c…_ppc64` |
| `nevra_module_stream` | 472,967 | `…::<module>:<stream>` | `AppStream-8.7.0.GA:Cython-0:0.28.1-7.module+el8.1.0+3111+de3f2d8e.src::python27:2.7` |
| `stream_registryurl_digest` | 393,636 | `registry.redhat.io/<ns>/<img>@sha256:<hex>_<arch>` | `Red Hat Ceph Storage 8:registry.redhat.io/rhceph/rhceph-8-rhel9@sha256:2325…` |
| `leaf_versionless` | 232,161 | bare `name` (no epoch, no arch) | `red_hat_enterprise_linux_10:tar` |
| `nevra_src` | 123,867 | `name-EPOCH:ver-rel.src` | `5Client-5.7.Z:java-1.6.0-openjdk-1:1.6.0.0-1.23.1.9.10.el5_7.src` |
| `imagepath_nodigest` | 72,286 | `<ns>/<img>` (no digest) | `red_hat_openshift_container_platform_4:openshift4/ose-tests` |
| `leaf_versionless_src` | 36,930 | bare `name.src` | `red_hat_enterprise_linux_8:tar.src` |
| `nevra_noarch_or_other` | 33,895 | NEVRA with rare arch (ia64/ppc) | `4AS-LACD:java-…-0:….el4.ia64` |
| `stream_other_digest` | 2,607 | bare `<name>@sha256:…_<arch>` (generic, no ns) | `9Base-RHOSE-4.17:rhcos@sha256:1be4…_aarch64` |
| `leaf_bare` | 1,821 | product node used directly (no `:`) | `red_hat_products`, `Red Hat JBoss Web Server 2.1` |

### 3a. Structural parsing rules **[triage.py:1746 `_parse_pkg_from_product_id`]**
1. Strip module suffix first: `pid.split('::')[0]`.
2. Component = everything after the **first** `:` (parent may itself contain no colon in practice;
   epoch colon is the 2nd `:`).
3. NEVRA detection: `-(\d+):` = the epoch colon → `name` before it, `ver-rel[.arch]` after.
   Strip trailing `.<arch>` in `{aarch64,x86_64,ppc64le,s390x,i686,i386,noarch,src}`.
4. No epoch colon → bare package name (version-less leaf).

### 3b. Registry-URL PIDs (newer layered products)
`<Human Product Name>:registry.redhat.io/<ns>/<img>@sha256:<hex>_<arch>` — the component is a
**full registry URL**, not a Brew image-path. Example (CVE-2024-45339, `fixed`):
`Red Hat OpenShift AI 2.16:registry.redhat.io/rhoai/odh-model-controller-rhel8@sha256:6cf740…`.
Contrast the older Brew-path form `8Base-RHOSE-4.8:openshift4/ose-cli@sha256:…`. Both carry a
per-arch suffix after the digest (`_amd64`, `_ppc64le`, …).

### 3c. Digest arch suffix (after `@sha256:<hex>`)
`_amd64` 315,911 · `_ppc64le` 230,424 · `_arm64` 223,216 · `_s390x` 215,698 · `_aarch64` 629.
Note digests use `amd64/arm64`; RPM NEVRAs use `x86_64/aarch64` — different arch vocabularies
between the two identity systems. **[triage.py:1654 `_extract_sha256`]** strips the `_<arch>` tail.

### 3d. `::module:stream` suffix
Top module streams (refs): `::virt:rhel` 76,494, `::container-tools:rhel8` 49,016,
`::virt:av` 34,262, `::mariadb:10.5`, `::mysql:8.0`, `::postgresql:15`, `::python39:3.9`,
`::perl:5.32`, `::nodejs:18`. Parsed by `pid.split('::',1)[1]` **[triage.py:1548 `_pid_module_stream`]**.
A PID with `::` is a **module build**; matching requires the installed version to also be a
module build (`.module+` in release) — §6, and the perl gap in §9.

### 3e. Epoch conventions
NEVRA epoch prefix distribution (refs): `0:` 1,876,386 · `1:` 470,650 · **none** 375,885 (bare
leaf PIDs + no-epoch NEVRAs) · `3:` 67,230 · `2:` 58,657 · `32:` 34,856 (glibc) · `15:`,`4:`,`5:`,
`17:` … Higher epoch always wins; when one side lacks an epoch it is propagated from the other
(same source pkg) **[triage.py:19 `compare_versions`, :1639 `_normalize_epoch`]**.

### 3f. `.src` semantics — binary↔source relationship
Two `.src` forms coexist and mean different things:
- **Versioned** `name-EPOCH:ver-rel.src` (123,867 refs) — a specific **source build** listed
  alongside its per-arch binaries, usually in `fixed` (the SRPM that carries the fix).
  Purl `pkg:rpm/redhat/<name>?arch=src`.
- **Version-less** `parent:name.src` (36,930 refs) — the **source package as a whole**, in
  `known_affected`/`known_not_affected` (e.g. `red_hat_enterprise_linux_8:tar.src`). Acts as a
  wildcard over all versions.

The source PID is what the binary→source alias (§8, step 5) keys on: a binary subpackage
(`perl-libs`) is aliased to its source (`perl`) only when a `.src` PID exists whose VR equals the
installed VR **or** which is version-less **[triage.py:1155 `_src_alias_names`]**. Red Hat VEX
*also* enumerates every binary subpackage per arch (see §9), so the alias is often not needed.

---

## 4. Identity Systems

### 4a. purl (`product_identification_helper.purl`) — per type
Mined by `analysis/mine_vex.py` (`tree_purl_types`, `purl_qparams`). Counts = product-tree nodes.

| Type | Nodes | Exact shape | Query params |
|---|---:|---|---|
| `rpm` | 1,916,489 | `pkg:rpm/redhat/<name>?arch=<a>` | `arch`, `epoch`, `rpmmod` |
| `oci` | 1,066,138 | `pkg:oci/<img>@sha256:<hex>?arch=<a>&repository_url=<reg>/<ns>/<img>&tag=<tag>` | `repository_url`, `tag`, `arch` |
| `maven` | 21,284 | `pkg:maven/<group>/<artifact>?repository_url=…&type=pom` | `repository_url`, `type`, `classifier` |
| `npm` | 6,787 | `pkg:npm/<name>@<ver>` | — |
| `generic` | 2,975 | `pkg:generic/redhat/<name>` (e.g. `rhcos`) | — |
| `golang` | 2 | `pkg:golang/redhat/<name>` | — |
| `pypi` | 2 | `pkg:pypi/<name>` | — |

Global qparam frequency: `arch` 2,767,907 · `repository_url` 1,074,615 · `tag` 982,064 ·
`rpmmod` 447,973 · `epoch` 417,601. Notable shapes:
- RPM module: `pkg:rpm/redhat/perl-Math-Complex?rpmmod=perl:5.30` (rpmmod = module:stream).
- RPM namespaced: `pkg:rpm/redhat/rhoai/odh-notebook-controller-rhel8?arch=src` (RHOAI RPMs carry
  a namespace path inside the rpm purl).
- OCI no-digest (product-tree leaf): `pkg:oci/elasticsearch6-rhel8?repository_url=registry.redhat.io/openshift-logging/elasticsearch6-rhel8`.
- OCI full (digest build): `pkg:oci/ose-cluster-autoscaler-rhel9@sha256:ebca…?arch=amd64&repository_url=registry.redhat.io/openshift4/ose-cluster-autoscaler-rhel9&tag=v4.19.0-…assembly.stream.el9`.

**Load-bearing:** the engine keys image matching on the OCI purl — exact `repository_url` match
first, then `pkg:oci/<name>` package-name equality as fallback (bridges Brew-label namespace ≠
registry namespace without hardcoding) **[triage.py:1268 `_purl_matched_leaf_pids`, :1238 `_build_image_purl`]**.
Go/Python are effectively never tracked as purls (2 each) — Go modules are assessed at the
containing image or RPM level, not directly.

### 4b. CPE (`product_identification_helper.cpe`)
Part distribution: `cpe:/a` (application) 61,949 · `cpe:/o` (OS) 29,610. Structure:
`cpe:/{a|o}:redhat:<product>[:<version>[::<edition/el-tag>]]`. Top shapes (nodes):

| CPE prefix | Nodes | Used by |
|---|---:|---|
| `cpe:/o:redhat:enterprise_linux` | 23,464 | RHEL base whole-product nodes |
| `cpe:/a:redhat:enterprise_linux` | 7,804 | RHEL app-stream nodes (`:8::appstream`) |
| `cpe:/a:redhat:openshift` | 4,365 | OCP streams (`:4.14::el8`) |
| `cpe:/a:redhat:rhel_eus` / `rhel_e4s` / `rhel_aus` / `rhel_tus` | 4,160 / 2,889 / 1,195 / 940 | long-life streams |
| `cpe:/a:redhat:rhel_software_collections` | 1,693 | SCL |
| `cpe:/a:redhat:openstack` / `ceph_storage` / `ansible_automation_platform` | 1,501 / 1,195 / 1,335 | layered |

- **`cpe:/o` vs `cpe:/a`:** the same RHEL major appears as both — `cpe:/o:redhat:enterprise_linux:8`
  (the OS product node) and `cpe:/a:redhat:enterprise_linux:8::appstream` (the AppStream repo). The
  `::` edition tail (`::appstream`, `::base`, `::fastdatapath`, `::el9`) names the repo/RHEL variant.
- **Image-label CPE ↔ product-tree CPE:** a scanned image carries a label CPE like
  `cpe:/a:redhat:openshift:4.12::el8`; the engine prefix-matches it against the VEX parent node's
  CPE (`cpe:/a:redhat:openshift:4`), component-wise — empty components are wildcards, and a shorter
  VEX version prefix-covers a longer image version (`4` covers `4.12`) **[triage.py:302 `_cpe_prefix_match`, :409]**.
- Catch-all `red_hat_products` has the **bare** vendor CPE `cpe:/a:redhat` (only 1 token after
  vendor) — that single-token shape is how the engine detects it **[triage.py:1971 `_is_catchall_not_affected`]**.

### 4c. Digests
`@sha256:<hex>` appears in 1,492 files (of 7,212) — the image-tracking corpus. A digest is
content-addressed → globally unique → a statement about `img@sha256:X` describes **one exact
build**. This is what makes per-build overrides sound (§5, §8). Same image name gets **many**
digest PIDs (one per rebuild/arch); each may carry a different verdict.

### 4d. Relationships — only `default_component_of`
**3,916,434 relationships, 100% `category = "default_component_of"`** (mine_vex `relationship_categories`).
Each links a component `product_reference` to a parent `relates_to_product_reference`, minting the
composite `full_product_name.product_id = <parent>:<component>`. This composite is the PID used
everywhere in `product_status`. Nothing else (no `optional_component_of`, `external_component_of`).
Branch categories that build the tree: `product_version` 3,014,533 · `product_name` 91,559 ·
`product_family` 54,537 · `architecture` 24,675 · `vendor` 7,212 (one per file).

---

## 5. Statement Semantics

All under `vulnerabilities[]` (usually one entry per file). Mined by `analysis/mine_vex.py`.

### 5a. `product_status` — 4 keys (files where non-empty / 7,212)
| Key | Files | Meaning |
|---|---:|---|
| `known_affected` | 6,048 | product is vulnerable |
| `known_not_affected` | 4,375 | assessed, not vulnerable (see flags for why) |
| `fixed` | 4,136 | fix shipped at this NEVRA/build |
| `under_investigation` | 146 | not yet assessed → engine treats as vulnerable |

**Co-occurrence** (top): `fixed+known_affected+known_not_affected` 2,437 files ·
`known_affected` only 1,724 · `fixed+known_affected` 933 · `known_affected+known_not_affected` 822
· `fixed+known_not_affected` 536 · `known_not_affected` only 480. So most files mix statuses across
products — a per-PID scoped lookup is mandatory, never a document-level verdict.

### 5b. `flags` (5 labels) — all mean "not affected" **[triage.py:1122 `_NOT_AFFECTED_FLAGS`]**
`vulnerable_code_not_present` 4,142 · `component_not_present` 546 ·
`vulnerable_code_not_in_execute_path` 334 · `vulnerable_code_cannot_be_controlled_by_adversary`
65 · `inline_mitigations_already_exist` 25. A flagged PID = additional not-affected evidence,
merged with `known_not_affected`. Each flag lists `product_ids` (and a CVSS justification).

### 5c. `threats` — per-product severity + KEV
`category=impact` 7,286 files · `category=exploit_status` 26 files. Impact `details` ∈
**{Moderate 4,043, Low 1,992, Important 1,221, Critical 30}** (Red Hat's 4-level scale) and lists
the `product_ids` it applies to → this is the **authoritative per-product severity map**
**[triage.py:1807 `_build_pid_severity_map`]**. `exploit_status` (26 files) = CISA **KEV**:
`details = "CISA: https://www.cisa.gov/known-exploited-vulnerabilities-catalog"`.

### 5d. `remediations` (4 categories) + details vocabularies
| Category | Refs | `details` vocabulary (top) | CVE-page row it renders |
|---|---:|---|---|
| `vendor_fix` | 32,105 | RHSA errata text/URL ("For details on how to apply this update…") | fix available |
| `no_fix_planned` | 5,224 | **`Will not fix` 2,507**, **`Out of support scope` 2,717** | "Will not fix" / "Out of support scope" |
| `none_available` | 4,245 | **`Affected` 2,212**, **`Fix deferred` 2,033** | "Affected" / "Fix deferred" |
| `workaround` | 3,198 | mitigation prose ("Mitigation for this issue is either not avail…") | mitigation note |

Operational meaning: a `known_affected` PID + `no_fix_planned/none_available` = a permanent
"Will not fix / Out of support / Fix deferred" row — still a true POSITIVE (no fix will come),
surfaced as such **[triage.py:2423-2457]**. `vendor_fix` co-occurs with `fixed` NEVRAs.

### 5e. `scores`
`cvss_v3:3.1` 5,909 · `cvss_v3:3.0` 1,051 · `cvss_v2:2.0` 237. Each score lists `products`.
Used only as a **severity fallback** (v3 `baseSeverity` → RH scale) when no `impact` threat scopes
to the finding **[triage.py:1945]**.

### 5f. Co-occurrence rules mined (design-critical)
- **Digest `known_not_affected` + generic `known_affected` for the same image** = per-build
  override: the exact build cleared even though the image family is generally affected
  (spot-check #3). Engine: our-digest statement wins over generic **[triage.py:2607-2638, :1443]**.
- **Mixed severities per image across builds:** different digest PIDs of one image can carry
  different impact ratings; only a *uniform* rating across builds is taken as the image's rating,
  else skipped as ambiguous **[triage.py:1859-1880]**.
- **`known_affected` + `known_not_affected` at equal scope** → conservative: affected wins
  **[triage.py:1499, :2622]**.

### 5g. Red Hat errata policy (the governing sentence, applied in §6/§8)
> *"Unless explicitly stated as not affected, all previous versions of packages in any minor
> update stream of a product listed here should be assumed vulnerable, although may not have been
> subject to full analysis."*

Operationally: for a version-stream product, an installed version **older** than the newest fixed
stream is assumed vulnerable; **equal or newer** than the newest fix is not a "previous version"
→ not vulnerable **[triage.py:1449-1482, :2291]**.

---

## 6. Stream & Version Semantics (RPM)

### 6a. Backport model
Red Hat backports one CVE fix to multiple minor streams at **different upstream versions**.
Spot-check #2 (CVE-2020-11023, pkg `cpp`): `el9_0` fixed at `11.2.1-9.5.el9_0`, `el9_2` at
`11.3.1-4.4.el9_2`, `el9_4` at `11.4.1-4.el9_4`, `el9_5` at `11.5.0-5.el9_5`. A naive "installed
< some-fix" comparison is wrong across streams — the correct fix depends on the installed stream.

### 6b. Validated comparison algorithm **[triage.py:2291 `_compare_fixed_rpm`]**
1. Detect installed minor stream from the `.el<N>_<M>` (or `module+el<N>.<M>`) marker
   **[:1673 `_detect_rhel_minor`]**.
2. If installed has a minor stream → compare **only** against `fixed` NEVRAs of the **same**
   minor stream.
3. If a fix exists but **not in the installed stream yet** → **still vulnerable** (POSITIVE,
   "No fix in el<N>_<M>; fix in other streams: …").
4. If installed has **no** minor marker (GA package) → it must be `>=` **all** stream fixes
   (a newer-stream fix proves the GA baseline is still vulnerable).
5. Compare with epoch-aware RPM vercmp; missing epoch propagated **[:19, :1639]**.
   Result: installed `>=` fix → FALSE POSITIVE; installed `<` fix → POSITIVE.
- Reference fix preference: when multiple in-scope fixes match, RHEL **base-repo** fixes are
  reported over add-on builds (e.g. AppStream `1.26.19-3.el9_8` over Ansible `2.7.0-1.el9ap`)
  **[triage.py:2412]**.

### 6c. Stream-aware `known_not_affected`
A KNA from a **different** minor stream does not clear the installed one (backport status differs
per stream) **[triage.py:2383-2388]** — the "scoped-clear" precision guard.

### 6d. Module streams
Parallel versions coexist (`perl:5.26` vs `perl:5.32`, `nodejs:18` vs `20`, `postgresql:12/13/15`).
A VEX PID with `::module:stream` matches only an installed **module** build (`.module+` in
release); a module PID never clears a non-module install and vice-versa
**[triage.py:2376, :1555 `_version_is_module_stream`]**. This guard is the root of the perl gap (§9).

### 6e. Epoch normalization
`compare_versions` parses `EPOCH:VER-REL`; higher epoch always wins; when the VEX fix omits the
epoch the RPM carries, it is propagated so the same-source packages compare correctly
**[triage.py:19, :1639 `_normalize_epoch`]**. Example epoch tokens seen: `0:` (dominant), `1:`,
`2:`, `3:`, `32:` (glibc), `15:` (dnsmasq/…).

---

## 7. Scanner-Side Model (RHACS)

Mined by `analysis/mine_scans.py` (SAMPLED — 766 distinct images of 13,745: 250 quay art-dev,
500 registry.redhat.io, 13 registry.access.redhat.com, 2 docker.io, 1 quay-other) and
`analysis/mine_sbom.py` (SAMPLED — 52 SBOMs, 24,241 packages, avg 466/image). A scan file is
`{name{registry,remote,tag,fullName}, metadata.v1.labels{}, scan.components[]}`.

### 7a. Component `source` types + naming (sampled component counts)
| SOURCE | Count | Name form | Location | Version form |
|---|---:|---|---|---|
| `OS` | 140,245 | RPM binary name (`grep`, `libgcc`) **+ image-identity pseudo-comps** | `var/lib/rpm` | `N-R.elN[_M]` (`3.6-5.el9`, `11.4.1-4.el9_4`) |
| `GO` | 67,808 | module path (`github.com/prometheus/common`, `golang.org/x/net`) | `usr/bin/<binary>` | `vX.Y.Z` (55,249) or `v0.0.0-<ts>-<hash>[+dirty]` pseudo (10,387) |
| `JAVA` | 10,716 | `group:artifact` (`io.fabric8:kubernetes-model-extensions`) | `…/<jar>.jar` | `4.0.5.redhat-00004` |
| `NODEJS` | 4,215 | bare name (`shell-quote`) | `…/package.json` | often **empty** |
| `PYTHON` | 4,211 | dist name (`urllib3`) | site-packages | PEP440 |
| `RUBY` | 95 | gem name | — | gem ver |

Matching-side implications: OS→RPM path (name matches VEX `pkg:rpm` NEVRA); GO→never in VEX
directly (assessed at image/RPM level); JAVA→VEX bare `artifact` (engine strips `group:` prefix);
NODEJS empty version → name-only match.

### 7b. Image-identity pseudo-components (SOURCE=OS, name contains `/`)
The scanner emits the **image's own identity** as OS pseudo-components. The `name` is the **image
path** (`namespace/image[-rhelN][-operator]`); the buildinfo path is the **location**, not the name
(`name` literally ending in `labels.json`: 0 occurrences — correcting a common misreading). Two forms:

| Location | Count | `name` example | `version` example | Version meaning |
|---|---:|---|---|---|
| `root/buildinfo/labels.json` | 4,575 | `openshift/openshift-enterprise-base-rhel9` | `1765773350` | epoch-seconds build time |
| `root/buildinfo/Dockerfile-<ns>-<img>-<NVR>` | 434 | `3scale-amp2/3scale-rhel7-operator` | `1.16.5-2` | Brew NVR-style |

These carry the `-rhelN` variant and the image namespace — the engine routes any `/`-containing
component to the non-RPM image path (§8) and uses these for identity, never RPM version compare.

### 7c. Image labels (`metadata.v1.labels`) — presence in 766 images
`name` 762 · `com.redhat.component` 762 · `release` 762 · `version` 762 · `architecture` 762 ·
`vcs-ref` 762 · **`cpe` 608** · `io.openshift.build.commit.id` 357 · `io.openshift.release.operator`
87 · `org.jboss.product` 32. (So `com.redhat.component` and `cpe` are both real, present in
99% / 79% of images — VEX_TRIAGE docs mention only `name`/`cpe`.) Example triple:
`name=openshift/ose-network-metrics-daemon-rhel9`, `cpe=cpe:/a:redhat:openshift:4.20::el9`,
`fullName=quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:29a8…`.

### 7d. Label-namespace ≠ registry-path-namespace (measured; task cited "139/747")
Namespace = first path segment after host (registry side) vs first segment of the `name` label
(label side); denominator = distinct images having both.
- **All images:** **336 / 734 mismatch (45.8%)**. By registry namespace: `openshift-release-dev` 248
  (structural — every art-dev image's registry path is `openshift-release-dev`, label says
  `openshift`), `openshift4` 50, `rhoai` 21 (Brew `managed-open-data-hub` → registry `rhoai`),
  `amq7` 10, `rhbk` 2, `kmm` 2.
- **Published only (excl. art-dev structural):** **88 / 486 mismatch (18.1%)** — genuine
  cross-namespace label errors on registry.redhat.io/.access (`openshift`↔`openshift4` for
  frr/ingress-node-firewall, `managed-open-data-hub`↔`rhoai`, `keycloak`↔`rhbk`,
  `kernel-module-management`↔`kmm`, `amq-broker-7`↔`amq7`).
- **Reconciliation with the task's "139/747" (18.6%):** the *rate* matches the **published-only,
  art-dev-excluded** cut — measured 18.1% (88/486); an independent registry.redhat.io-only probe
  gave 17.4% (110/631). So the reference figure **excludes art-dev** (whose registry path is the
  meaningless shared `openshift-release-dev`, making its 45.8% all-image rate an artifact). The
  denominators differ by sample composition; the ~18% rate is the reproduced evidence.
- **Operational rule (holds regardless of the exact count):** the registry pull path is
  authoritative for the RHEL variant, the `name` label is secondary — bridged by OCI purl
  name-equality **[triage.py:565-571, :1260]**.
- **Stale `rhelN` labels:** sharper test = label's `-rhelN` ≠ actual base OS from
  `scan.operatingSystem` → **8/718** genuinely stale (e.g. `compliance/openshift-compliance-must-
  gather-rhel8` label says rhel8 but OS is `rhel:9`, path even says `-rhel9`). The engine re-derives
  the RHEL major from the pull path, overriding the stale label **[triage.py:568]**.

### 7e. quay release-payload digests vs registry.redhat.io digests
- **registry.redhat.io** (500 sampled): per-image repo path names the image —
  `registry.redhat.io/3scale-amp2/3scale-rhel7-operator@sha256:7aeeb…`. Identity from the path.
- **quay art-dev** (250 sampled): **all** OCP release components share ONE repo
  `quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:…` — the path does **not** name the image;
  identity must come from the `name`/`com.redhat.component` label or SBOM. This is why label-based
  identity (and the label↔path mismatch of 7d) matters most for OCP core images.
- `registry.access.redhat.com` also appears (13) — same per-image-path style as registry.redhat.io.

### 7f. SBOM (SPDX) relationships — sampled 52 files
Only two relationship types: **`CONTAINED_BY` 36,296** and **`GENERATED_FROM` 10,468**.
- **`GENERATED_FROM`** = binary-RPM → source-RPM (the alias source for triage's `sbom_src_map`):
  4,733 cross (`libgcc`→`gcc`, `glibc-common`→`glibc`, `bzip2-libs`→`bzip2`,
  `python3-setuptools-wheel`→`python-setuptools`, `ncurses-libs`→`ncurses`) + 5,735 self-referential.
- **`CONTAINED_BY`** = package → a **Distribution** pseudo-package (`Red Hat Enterprise Linux
  Server`, purpose OPERATING-SYSTEM) **and** a **Repository** pseudo-package whose name is a CPE
  (`cpe:2.3:o:redhat:enterprise_linux:8:*:baseos:*…`) — i.e. the repoid/RHEL variant, **not**
  package→package. External refs use `cpe23Type` (334), not purl (RPMs identified by CPE here).
  Read: the SBOM confirms both the binary→source lineage and the RHEL/repo the package came from.

---

## 8. The Matching Problem & Decision Ladder

The core spec: reconcile a **scanner identity** (RHACS component: name/version/source + image
labels/digest) against a **VEX identity** (a `product_status` PID). This is the consolidation of
all session-validated rules. Entry point **[triage.py:2583 `_audit_verdict`]**.

### 8a. Scoping predicate — evaluated for *every* candidate PID first **[triage.py:348 `_pid_in_scope`]**
A PID is in scope for the workload iff:
- **UBI/RHEL:** PID is a RHEL base repo of the workload's RHEL major (`_is_rhel_base_product`,
  derived from product-tree names starting "Red Hat Enterprise Linux" — no hardcoded stream list).
- **OCP:** RHEL base repos **+** any parent whose name is "Red Hat OpenShift Container Platform
  `<v>`", version prefix-matched (VEX `4` covers all `4.x`; `4.21` matches only `4.21.x`) **+** CPE
  prefix match of the image-label CPE against the VEX parent CPE **+** any product mentioning the
  workload's RHEL major (`_is_any_rhel_ver_product`, catches Fast Datapath etc.).
- **Operator:** RHEL base repos **+** catalog prefixes (`ns_vex_prefixes.json`) **+** the dynamic
  `vex_ns_map` (registry-namespace → VEX product, built from OCI purls in the tree at load time).

### 8b. The ordered ladder (first decisive rung wins)
| # | Rung | Condition (in scope unless noted) | Verdict | Engine site |
|---|---|---|---|---|
| 1 | **Vendor catch-all** | `red_hat_products` (or any bare `cpe:/a:redhat` node) ∈ `known_not_affected`/not-affected flag | **FALSE POSITIVE** "No supported Red Hat product affected" | `_is_catchall_not_affected` :1971 / :2602 |
| 2 | **Our-digest override** | any PID contains the scanned image's exact `@sha256:` digest | authoritative per-build: KA/UI→**POSITIVE**, KNA/fixed→**FALSE POSITIVE** (applies to RPM *and* non-RPM) | :2607-2638 |
| 3a | **Image identity via OCI purl** | image candidates {ref-repo (authoritative), `name`-label repo (secondary)} match a VEX OCI purl by exact `repository_url`, else by `pkg:oci/<name>` equality | matched generic image PID → POSITIVE/FALSE POSITIVE | `_purl_matched_leaf_pids` :1268; `_image_vex_lookup` :1293 |
| 3b | **Image identity via path/generic** | image-path PID normalized (`ose-etcd-rhel9`→`etcd`) == `ocp_component`; or generic `pkg:generic/redhat/<c>` (rhcos↔rhel-coreos) | same | `_normalize_vex_image_core` :1189; :1335-1362 |
| 4 | **Same-image other-build evidence** | matched image PIDs for *other* builds, scored by RHEL-variant quality (exact `-rhelN`=2, version-neutral=1, other RHEL=0); SHA-exact (spec=2) overrides generic (spec=1); at equal quality, affected wins | POSITIVE / FALSE POSITIVE / `POSITIVE_OTHER_RHEL` | :1370-1545 |
| 5 | **Component NEVRA/name in-scope** (RPM path) | package name ∈ names-to-match; dist-tag + minor-stream + module-stream + CPE scoping; then §6 version compare | KNA→FP; fixed→compare; KA→POSITIVE; UI→POSITIVE | `_audit_rpm` :2346 |
| 5s | **src-alias expansion** | binary comp aliased to source name when a `.src` PID's VR == installed VR **or** a version-less `.src` exists; also Maven `group:artifact`→`artifact`, SBOM binary→source | expands names-to-match for rung 5 | `_src_alias_names` :1155; `_resolve_comp` :1131 |
| 6 | **Product-family clear** (non-RPM fallthrough) | all in-scope PIDs for this CVE are `known_not_affected`/`fixed`, none affected/UI | **FALSE POSITIVE** "no affected entry" (scoped-clear) | `_audit_nonrpm_fallthrough` :2207 |
| 7 | **Errata policy** (version-streams) | no direct match, but versioned OCP/RHOSE `fixed` streams exist: installed **older** than newest fix → assumed vulnerable; **equal/newer** → not | POSITIVE / FALSE POSITIVE (`errata_fixed`/`errata_not_previous`) | :1449-1535, :2291 |
| 8 | **Related-products evidence** | same package in out-of-scope products marked with the workload's RHEL major **or** version-neutral PIDs (no el/rhel marker) | only-clear→FALSE POSITIVE; any affected→POSITIVE (conservative) | :2471-2503; `_is_version_neutral_product` :1711 |
| 9 | **Truly absent** | component not tracked in any in-scope VEX entry | **⚠️ NOT ASSESSED** "not tracked in VEX" | :2505, :2020 |

**RPM vs non-RPM split** happens after rungs 1-2 **[triage.py:2645-2675]**: a `/` in the component
name (RHACS image-identity pseudo-component) **or** absence of an `.elN` marker routes to the
non-RPM path (rungs 3,4,6,7,8,9); an `.elN` marker or `SOURCE=OS` routes to the RPM path
(rungs 5,5s, then 8,9). Rungs 1,2 precede both.

### 8c. Scanner-identity × VEX-identity pairings (every observed pairing + resolution)
| Scanner side | VEX side it matches | Rung |
|---|---|---|
| image digest (`@sha256:` in `image_ref`) | `stream:img@sha256:X_arch` PID with same X | 2 |
| image ref repo / `name` label | OCI purl `repository_url=` / `pkg:oci/<name>` | 3a |
| `ocp_component` (from name label) | image-path PID `ose-<c>-rhelN` / generic `<c>` | 3b/4 |
| RPM binary name + `.elN_M` version (`SOURCE=OS`) | `parent:name-E:ver-rel.elN_M.arch` in scope | 5 |
| RPM binary subpackage (`perl-libs`, `ceph-mon`) | source `.src` PID (`perl`,`ceph`) via alias | 5s |
| Maven `group:artifact` (`SOURCE=JAVA`) | bare `artifact` PID (`pkg:maven`) | 5s |
| Go module path (`SOURCE=GO`) | *(never tracked directly)* → containing image/RPM | 3/6 |
| any component, family assessed clear | in-scope KNA/fixed only | 6 |
| OCP version vs RHOSE-`4.x` fixed streams | version comparison per errata policy | 7 |
| component in related RHEL-N / version-neutral product | out-of-scope KA/fixed/KNA | 8 |
| component absent everywhere in scope | — | 9 |

### 8d. Severity, state, and fix version come from the DECISIVE PID
Once a rung fires, severity/state/fix are read from **that** PID's `threats`/`remediations`, not the
document header:
- **Severity** priority chain **[triage.py:1825 `_resolve_base_severity`]**: (1) OCI-purl-matched
  PID's impact — within this, **own digest > generic (no-digest) > other builds only if uniform**;
  (2) image-level PID impact; (3) component-name PID impact; (4) in-scope KA/fixed impact (highest);
  (5) `aggregate_severity`; (6) any impact threat; (7) CVSS `baseSeverity`; (8) RHACS scan severity.
- **State/justification** **[triage.py:2512 `_derive_state`]**: from the decisive PID's remediation
  `details` — `no_fix_planned`→"Will not fix"/"Out of support scope"; `none_available`→"Fix
  deferred"/"Affected".
- **Fix version:** the matched `fixed` NEVRA, preferring RHEL **base-repo** references over add-on
  builds **[triage.py:2412]**.

---

## 9. Open Questions / Ambiguities

1. **perl-libs "src-alias failure" — investigated; it does NOT fail in current data, and the
   cause is not the src-alias** (engine-driven: `analysis/investigate_perl.py` + live
   `triage._audit_verdict` + real-scan grep). Findings:
   - The perl `.src` PID is **not** shaped abnormally
     (`AppStream-8.10.0.Z.MAIN.EUS:perl-4:5.32.1-474.module+el8.10.0+24099+8aa2f756.src::perl:5.32`).
   - Red Hat VEX **enumerates every perl binary subpackage** per arch — `perl-libs` appears as its
     own NEVRA (48-108 per-arch entries in CVE-2026-48962 / CVE-2023-47038) — so `perl-libs` matches
     **directly**; the src-alias is never exercised. Live-engine verdicts confirm it works: installed
     older → POSITIVE ("< fix 5.32.1-474…"), installed ≥ fix → FALSE POSITIVE.
   - **Version schemes align on both sides**, so no guard misfires in practice: **el9 perl is
     un-modularized** (plain `.el9` — sampled scans show `perl-Exporter 5.74-461.el9` etc.; VEX PIDs
     are plain `perl-4:5.32.1-481.el9`, no `::`), while **el8 perl is a module** (`.module+el8…` on
     both the RPM release *and* the VEX `::perl:5.XX` PID). Sampled scans: **8,038 plain vs 43 module**
     perl RPMs, and el8 module RPMs always carry `.module+` — so both sides agree.
   - **Two latent fragilities exist but are masked (not observed firing):** (a) the module-stream
     guard (§6d) would skip every el8 perl PID if a scanner ever reported an el8 perl RPM *without*
     `.module+` — reproducible only with a synthetic version (`perl-libs 4:5.32.1-472.el8_10` →
     ⚠️ NOT ASSESSED), not with real scan data; (b) `_src_alias_names` aliases only on VR-equality or
     a version-less `.src` wildcard (2/19 perl-source files have only a versioned `.src`) — but this
     path is unreached because binaries are enumerated directly. A rewrite should still remove both
     fragilities (don't gate the binary→source alias on VR-equality; treat module/non-module by the
     RHEL major, not by a `.module+` substring).
2. **Dist-tag ≠ product.** `el9`/`el8` appear under RHOSE, RHEL base, and layered products alike
   (§2). Scoping must use the **parent PID**, not the dist-tag alone. `el9fdp`/`el9cp`/`el8ost`
   live under *both* their dedicated product (`9Base-Fast-Datapath`) and OpenShift/OSP streams —
   a component can be in scope via more than one parent.
3. **Namespace ambiguity (`vex_ns_map`).** One registry namespace can map to several VEX parent
   products; the dynamic map is built per-CVE from OCI purls, so scope can vary by file. Undocumented
   namespaces fall back to purl package-name equality (§4a) — silent miss if neither matches.
4. **Version-neutral admissibility.** `red_hat_openshift_container_platform_4:openshift-clients`
   (no el/rhel marker) is admitted as related evidence because it "cannot contradict" the RHEL
   version — but it also cannot *confirm* the minor stream, so rung 8 verdicts on it are deliberately
   conservative, occasionally over-flagging.
5. **`fixed` without version verification (non-RPM).** For a non-RPM component where only a generic
   `fixed` PID matches (no digest, no version to compare), the engine returns POSITIVE ("fix exists;
   installed not verified") **[triage.py:2130]** — conservative, may over-report already-patched builds.
6. **Registry-URL vs Brew-path PIDs.** Newer layered products use full
   `registry.redhat.io/<ns>/<img>@sha256` PIDs (§3b) while OCP core uses Brew `openshift4/<img>`
   paths; both must be parsed for the same image — a rewrite should treat them uniformly via the
   OCI purl, which is present on both.
7. **Arch vocabulary mismatch.** Digests use `amd64/arm64`; NEVRAs use `x86_64/aarch64`. Any
   cross-identity arch reasoning must translate (the engine sidesteps this by ignoring the digest
   arch suffix).
8. **Under-investigation is rare (146 files) but load-bearing:** always treated as POSITIVE; a
   later regeneration may flip it — verdicts are only as fresh as the mirrored VEX file.

---

## Appendix A — Validation: 5 hand spot-checks against raw JSON

Every count above comes from the `analysis/` scripts. These 5 rules are additionally verified by
hand-reading raw VEX JSON (excerpts verbatim).

**SC-1 — `default_component_of` mints the composite PID** (CVE-2005-2541).
```json
{ "category": "default_component_of",
  "full_product_name": { "name": "tar.src as a component of Red Hat Enterprise Linux 8",
                          "product_id": "red_hat_enterprise_linux_8:tar.src" },
  "product_reference": "tar.src",
  "relates_to_product_reference": "red_hat_enterprise_linux_8" }
```
Confirms §4d: `<component>` + `<parent>` → `<parent>:<component>`, and the `.src` component form.

**SC-2 — multi-stream backport, different upstream per minor** (CVE-2020-11023, pkg `cpp`), from
`product_status.fixed`:
```
AppStream-9.0.0.Z.E4S:cpp-0:11.2.1-9.5.el9_0.x86_64
AppStream-9.2.0.Z.EUS:cpp-0:11.3.1-4.4.el9_2.x86_64
AppStream-9.4.0.Z.EUS:cpp-0:11.4.1-4.el9_4.x86_64
AppStream-9.5.0.Z.MAIN:cpp-0:11.5.0-5.el9_5.x86_64
```
Confirms §6a/§6b: 9.0→11.2.1, 9.2→11.3.1, 9.4→11.4.1, 9.5→11.5.0. Same-stream comparison mandatory.

**SC-3 — digest KNA overrides generic KA (per-build)** (CVE-2016-2183), same image:
```
known_affected (generic): red_hat_openshift_container_platform_4:openshift4/ose-openstack-cinder-csi-driver-rhel8-operator
known_not_affected (digest): 8Base-RHOSE-4.8:openshift4/ose-openstack-cinder-csi-driver-rhel8-operator@sha256:5613f5233463ef…_ppc64le
```
Confirms §5f/§8 rung 2: the exact build (`@sha256`) cleared though the family is generically affected.

**SC-4 — `no_fix_planned` = "Will not fix" with `known_affected`** (CVE-2005-2541):
`red_hat_enterprise_linux_10:tar` ∈ `known_affected`, and:
```json
{ "category": "no_fix_planned", "details": "Will not fix",
  "product_ids": ["red_hat_enterprise_linux_10:tar", "red_hat_enterprise_linux_6:tar", …] }
```
Confirms §5d: KA + `no_fix_planned` → permanent "Will not fix" POSITIVE row.

**SC-5 — vendor catch-all node** (CVE-2009-4487): product-tree node
```json
{ "name": "All currently supported Red Hat products", "product_id": "red_hat_products",
  "product_identification_helper": { "cpe": "cpe:/a:redhat" } }
```
and `red_hat_products ∈ known_not_affected`. Confirms §1g/§4b/§8 rung 1: bare `cpe:/a:redhat`
single-token vendor CPE → FALSE POSITIVE "No supported Red Hat product affected".

## Appendix B — analysis/ scripts (reproducible evidence)
| Script | Produces | Feeds |
|---|---|---|
| `mine_vex.py` | `vex_facts.json` (shapes, dist-tags, purls, CPEs, statement vocab) | §2,3,4,5,6 |
| `mine_products.py` | `products.json` (2,357 parents, layered) | §1 |
| `investigate_perl.py` | perl src-alias analysis | §9.1 |
| `find_spotcheck_cases.py` | spot-check candidate CVEs | App. A |
| `mine_scans.py`, `mine_sbom.py` | scanner + SBOM facts (sampled) | §7 |


