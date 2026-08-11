# VEX-MODEL.md — Red Hat CSAF-VEX Data Model (Ground-Truth Reference)

Reference documentation of Red Hat's CSAF-VEX data model and of the rules required to match
RHACS scanner findings against it. Every count and example below is **mined from the data**,
not from memory.

**Corpus measured:** `data/vex/CVE-*.json` = **7,212 files**, 0 parse errors. Scanner side
sampled from `data/scans/*.json` (13,745 files) and `data/sbom/*.sbom` (13,109 files) — see §7.

> **Re-measured 2026-08-05 — the mirror has grown to 18,273 files** (5,398,502 product-tree
> nodes, 7,747,974 `product_status` refs). Ratios below were re-derived, not rescaled; where a
> figure or rule changed it is corrected in place and marked **(2026-08-05)**. Red Hat
> regenerates VEX daily, so absolute counts drift — the shapes and rules are the durable part.

**Identity of record: the purl, not the `product_id`.** Red Hat's own
[csaf-lib](https://github.com/RedHatProductSecurity/csaf-lib) models `product_id` as an opaque
string and parses only `product_identification_helper.purl` (via `PackageURL.from_string`).
**99.88% of all 7,747,974 status refs resolve to a purl** with no string parsing —
`relationships[].product_reference` → product-tree node → purl. The PID grammar in §3 is a
reverse-engineered fallback for the remainder (upstream-project pseudo-components such as
`jackson-databind`, and bare product nodes), not the primary identity. (2026-08-05)

**Format:** CSAF 2.0, `document.category = "csaf_vex"`, publisher `Red Hat Product Security`,
engine `Red Hat SDEngine`. One file per CVE. Three top-level objects: `document`,
`product_tree` (`branches` + `relationships`), `vulnerabilities[]`.

**Counting conventions.** "refs" = occurrences of a product_id across all `product_status`
lists in all files (a PID appears once per arch, so refs ≈ per-arch statement count).
"files" for a status key = number of `vulnerabilities` entries where that key is non-empty
(denominator = 7,212). Distinct-parent counts dedupe the first `:`-segment.

---

## 1. The Product Universe

**2,357 distinct parent products** (first PID segment),
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
  and are admissible only as version-neutral related evidence.

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
findings. Counts are refs; "top parents" shows which parent products carry the tag. **A dist-tag alone does not pin the
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
`module+el8.<minor>` encodes minor as the 2nd component.

---

## 3. PID Grammar

A `product_id` in `product_status`/`threats`/`remediations`/`flags` is either a bare product-tree
node or a `relationship.full_product_name.product_id`. Counts are refs over the whole corpus:

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
| `module@arch` **(2026-08-05)** | 3,300 in 553 files | `<module>@<arch>` — Red Hat Hardened Images ("hummingbird") | `Red Hat Hardened Images:perl-main@aarch64` |

The `module@arch` shape carries **no package name and no version**: the component names a
module, and only the purl gives the real identity —
`perl-main@aarch64` → `pkg:rpm/redhat/perl@5.42.2-524.hum1?arch=aarch64`. A NEVRA-style parse
yields a name that matches nothing and the statement silently reaches rung 9 ("not listed"),
which is a FALSE POSITIVE — one more reason identity must come from the purl.

### 3a. Structural parsing rules
1. Strip module suffix first: `pid.split('::')[0]`.
2. Component = everything after the **first** `:` (parent may itself contain no colon in practice;
   epoch colon is the 2nd `:`).
3. NEVRA detection: `-(\d+):` = the epoch colon → `name` before it, `ver-rel[.arch]` after.
   Strip trailing `.<arch>` — the **full** measured `arch=` vocabulary is 14 tokens
   **(2026-08-05)**, and the shorter set previously listed here left the arch glued to the
   version on 18,365 nodes (`0.9.8e-12.el5.i386`), which can never equal an installed NEVRA:

   | arch | nodes | | arch | nodes |
   |---|---:|---|---|---:|
   | `x86_64` | 677,953 | | `ppc64` | 10,000 |
   | `aarch64` | 570,326 | | `ppc` | 3,288 |
   | `ppc64le` | 496,558 | | `s390` | 3,085 |
   | `s390x` | 495,471 | | `i386` | 1,307 |
   | `src` | 237,534 | | `ia64` | 459 |
   | `noarch` | 234,844 | | `i586` | 226 |
   | `i686` | 65,069 | | `source` | 68 |

   Alternation order matters: `ppc64le` before `ppc64` before `ppc`, `s390x` before `s390`.
4. No epoch colon → bare package name (version-less leaf).
5. **RHEL parents now carry image-path components too** (Konflux era):
   `red_hat_enterprise_linux_9:redhat-user-workloads/bootc-image-builder-9-6` — a `/` in the
   component means an image even under a RHEL base product; never treat it as an RPM name.

### 3b. Registry-URL PIDs (newer layered products)
`<Human Product Name>:registry.redhat.io/<ns>/<img>@sha256:<hex>_<arch>` — the component is a
**full registry URL**, not a Brew image-path. Example (CVE-2024-45339, `fixed`):
`Red Hat OpenShift AI 2.16:registry.redhat.io/rhoai/odh-model-controller-rhel8@sha256:6cf740…`.
Contrast the older Brew-path form `8Base-RHOSE-4.8:openshift4/ose-cli@sha256:…`. Both carry a
per-arch suffix after the digest (`_amd64`, `_ppc64le`, …).

### 3c. Digest arch suffix (after `@sha256:<hex>`)
`_amd64` 315,911 · `_ppc64le` 230,424 · `_arm64` 223,216 · `_s390x` 215,698 · `_aarch64` 629.
Note digests use `amd64/arm64`; RPM NEVRAs use `x86_64/aarch64` — different arch vocabularies
between the two identity systems. strips the `_<arch>` tail.

### 3d. `::module:stream` suffix
Top module streams (refs): `::virt:rhel` 76,494, `::container-tools:rhel8` 49,016,
`::virt:av` 34,262, `::mariadb:10.5`, `::mysql:8.0`, `::postgresql:15`, `::python39:3.9`,
`::perl:5.32`, `::nodejs:18`. Parsed by `pid.split('::',1)[1]`.
A PID with `::` is a **module build**; matching requires the installed version to also be a
module build (`.module+` in release) — §6, and the perl gap in §9.

### 3e. Epoch conventions
NEVRA epoch prefix distribution (refs): `0:` 1,876,386 · `1:` 470,650 · **none** 375,885 (bare
leaf PIDs + no-epoch NEVRAs) · `3:` 67,230 · `2:` 58,657 · `32:` 34,856 (glibc) · `15:`,`4:`,`5:`,
`17:` … Higher epoch always wins; when one side lacks an epoch it is propagated from the other
(same source pkg).

### 3f. `.src` semantics — binary↔source relationship
Two `.src` forms coexist and mean different things:
- **Versioned** `name-EPOCH:ver-rel.src` (123,867 refs) — a specific **source build** listed
  alongside its per-arch binaries, usually in `fixed` (the SRPM that carries the fix).
  Purl `pkg:rpm/redhat/<name>?arch=src`.
- **Version-less** `parent:name.src` (36,930 refs) — the **source package as a whole**, in
  `known_affected`/`known_not_affected` (e.g. `red_hat_enterprise_linux_8:tar.src`). Acts as a
  wildcard over all versions.

> **Not always a wildcard (2026-08-05).** The wildcard reading was inferred from the PID's
> version-lessness, and the purl contradicts it on 168 refs: `red_hat_ceph_storage_6:python-asyncssh.src`
> → `pkg:rpm/redhat/python-asyncssh@2.9.0-5.el9cp`, `…rhel_ai_3:ffmpeg.src` → `6.1.5-2.el9ai`.
> Those nodes name a specific build. Verdict impact measured as nil on ceph + AAP images
> (4,180 rows), but a consumer reading the PID alone would treat a build-specific statement as
> covering every version.

The source PID is what the binary→source alias (§8, step 5) keys on: a binary subpackage
(`perl-libs`) is aliased to its source (`perl`) only when a `.src` PID exists whose VR equals the
installed VR **or** which is version-less. Red Hat VEX
*also* enumerates every binary subpackage per arch (see §9), so the alias is often not needed.

---

## 4. Identity Systems

### 4a. purl (`product_identification_helper.purl`) — per type
Counts = product-tree nodes.

| Type | Nodes | Exact shape | Query params |
|---|---:|---|---|
| `rpm` | 1,916,489 | `pkg:rpm/redhat/<name>[@<ver-rel>]?arch=<a>` — **versioned, see below** | `arch`, `epoch`, `rpmmod`, `distro`, `repository_id` |
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

**rpm purls carry the version (2026-08-05).** The version-less shape above is stale.
Of 3,966,621 rpm nodes, **2,745,460 (69.2%) carry `@version-release`**:

```
pkg:rpm/redhat/perl-XML-Parser@2.46-9.el9_6.1?arch=src
pkg:rpm/redhat/openssl@0.9.8e-12.el5?arch=i386
```

The remaining 1,221,161 are the genuinely version-less leaves (`red_hat_enterprise_linux_10:tar`).
There are **zero** nodes whose PID is a NEVRA while the purl lacks the version, so the purl is
never less informative than the PID. Three consequences for any consumer:

- **Percent-decoding is mandatory.** 230,752 purls (21.9%) write module builds as
  `2.4.37-51.module%2Bel8.7.0%2B18026`; without `unquote` both the `.module+` test (§6d) and
  the RPM version compare break.
- **Only the vendor namespace may be stripped.** 713 nodes carry a product path
  (`pkg:rpm/redhat/openshift4/ose-cli`), and that surviving `/` is what routes the component
  to the non-RPM ladder (§3a rule 5, §8b). Every rpm purl uses the `redhat` namespace
  (3,982,862 of 3,982,862), so strip it positionally, not by name.
- `rpmmod` carries the full module NSVCA (`httpd:2.4:8070020230131172653:bd1311ed`), richer
  than the PID's `::httpd:2.4`.

**Load-bearing:** image matching must key on the OCI purl — exact `repository_url` match
first, then `pkg:oci/<name>` package-name equality as fallback (bridges Brew-label namespace ≠
registry namespace without hardcoding).

**Two purl eras coexist, even inside one file.** Older nodes: purl name is the bare image
(`pkg:oci/ose-cli@…`) and `repository_url` is the **full repo path**
(`registry.redhat.io/openshift4/ose-cli`), `tag=` is a Brew NVR with a timestamp
(`v4.15.0-202404030309.p0…`). Newer (Konflux-era) nodes: purl name carries the namespace
(`pkg:oci/openshift/ose-cli@…`), `repository_url` is the **namespace only**
(`registry.redhat.io/openshift4`), and `tag=` is **epoch seconds** (`1781813947`).
Matching must compose the effective repo — `repository_url` + the purl name's last segment
when the URL doesn't already end with it — so both eras compare exactly.
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
  `cpe:/a:redhat:openshift:4.12::el8`; match it against the VEX parent node's CPE
  (`cpe:/a:redhat:openshift:4`) by prefix, component-wise — empty components are wildcards, and a
  shorter VEX version prefix-covers a longer image version (`4` covers `4.12`).
- Catch-all `red_hat_products` has the **bare** vendor CPE `cpe:/a:redhat` (only 1 token after
  vendor) — that single-token shape uniquely identifies it.

### 4c. Digests
`@sha256:<hex>` appears in 1,492 files (of 7,212) — the image-tracking corpus. A digest is
content-addressed → globally unique → a statement about `img@sha256:X` describes **one exact
build**. This is what makes per-build overrides sound (§5, §8). Same image name gets **many**
digest PIDs (one per rebuild/arch); each may carry a different verdict.

### 4d. Relationships — only `default_component_of`
**3,916,434 relationships, 100% `category = "default_component_of"`**.
Each links a component `product_reference` to a parent `relates_to_product_reference`, minting the
composite `full_product_name.product_id = <parent>:<component>`. This composite is the PID used
everywhere in `product_status`. Nothing else (no `optional_component_of`, `external_component_of`).
Branch categories that build the tree: `product_version` 3,014,533 · `product_name` 91,559 ·
`product_family` 54,537 · `architecture` 24,675 · `vendor` 7,212 (one per file).

---

## 5. Statement Semantics

All under `vulnerabilities[]` (usually one entry per file).

### 5a. `product_status` — 4 keys (files where non-empty / 7,212)
| Key | Files | Meaning |
|---|---:|---|
| `known_affected` | 6,048 | product is vulnerable |
| `known_not_affected` | 4,375 | assessed, not vulnerable (see flags for why) |
| `fixed` | 4,136 | fix shipped at this NEVRA/build |
| `under_investigation` | 146 | not yet assessed → treat as vulnerable |

**Co-occurrence** (top): `fixed+known_affected+known_not_affected` 2,437 files ·
`known_affected` only 1,724 · `fixed+known_affected` 933 · `known_affected+known_not_affected` 822
· `fixed+known_not_affected` 536 · `known_not_affected` only 480. So most files mix statuses across
products — a per-PID scoped lookup is mandatory, never a document-level verdict.

### 5b. `flags` (5 labels) — all mean "not affected"
`vulnerable_code_not_present` 4,142 · `component_not_present` 546 ·
`vulnerable_code_not_in_execute_path` 334 · `vulnerable_code_cannot_be_controlled_by_adversary`
65 · `inline_mitigations_already_exist` 25. A flagged PID = additional not-affected evidence,
merged with `known_not_affected`. Each flag lists `product_ids` (and a CVSS justification).

### 5c. `threats` — per-product severity + KEV
`category=impact` 7,286 files · `category=exploit_status` 26 files. Impact `details` ∈
**{Moderate 4,043, Low 1,992, Important 1,221, Critical 30}** (Red Hat's 4-level scale) and lists
the `product_ids` it applies to → this is the **authoritative per-product severity map**. `exploit_status` (26 files) = CISA **KEV**:
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
surfaced as such. `vendor_fix` co-occurs with `fixed` NEVRAs.

### 5e. `scores`
`cvss_v3:3.1` 5,909 · `cvss_v3:3.0` 1,051 · `cvss_v2:2.0` 237. Each score lists `products`.
Used only as a **severity fallback** (v3 `baseSeverity` → RH scale) when no `impact` threat scopes
to the finding.

### 5e-bis. Image statements only ever CLEAR (2026-08-05)

oci statements by shape × status, whole corpus:

| shape | known_not_affected | fixed | known_affected | under_investigation |
|---|---:|---:|---:|---:|
| with digest | 487,218 | 129,806 | **0** | 0 |
| no digest | 386,501 | 88,827 | 52,680 | 4,490 |

**Red Hat never marks a specific image build affected.** Per-build statements exist only in
the clearing direction; "affected" is asserted at the image-family level. Two consequences:

- a digest-pinned statement is the strongest evidence available for false-positive
  identification, and it is exactly the evidence that cannot be manufactured;
- no path can ever derive "this build is affected" from an image statement alone — that
  verdict has to come from the family plus the errata policy (§5g).

### 5f. Co-occurrence rules mined (design-critical)
- **Digest `known_not_affected` + generic `known_affected` for the same image** = per-build
  override: the exact build cleared even though the image family is generally affected
  (spot-check #3). Rule: our-digest statement wins over generic.
- **Mixed severities per image across builds:** different digest PIDs of one image can carry
  different impact ratings; only a *uniform* rating across builds is taken as the image's rating,
  else skipped as ambiguous.
- **`known_affected` + `known_not_affected` at equal scope** → conservative: affected wins.

### 5g. Red Hat errata policy (the governing sentence, applied in §6/§8)
> *"Unless explicitly stated as not affected, all previous versions of packages in any minor
> update stream of a product listed here should be assumed vulnerable, although may not have been
> subject to full analysis."*

Operationally: for a version-stream product, an installed version **older** than the newest fixed
stream is assumed vulnerable; **equal or newer** than the newest fix is not a "previous version"
→ not vulnerable.

**The sentence scopes itself to products *listed here*.** An unlisted product/component gets no
assumption in either direction — it is simply absent from Red Hat's per-CVE enumeration.
Triage semantics: absence cannot confirm a scanner finding, so a component/image/product with
**no statement naming it is FALSE POSITIVE ("not listed as affected")** — the only exceptions
are a component *named* in related products (§8 rung 8, conservative) and a VEX file that does
not exist at all (no enumeration to be absent from → the scanner finding stands).

> **Correction (2026-08-05) — "listed" means the PRODUCT, not the component.** The sentence
> governs *packages of a product listed here*, so when Red Hat lists our product as affected
> and simply does not name our image/component, the assumption applies and the row is
> **POSITIVE**, not a false positive. Proof, CVE-2026-42507:
>
> ```
> known_affected: red_hat_web_terminal:web-terminal/web-terminal-exec-rhel9
> our image:      web-terminal/web-terminal-tooling-rhel9     (same product, unnamed)
> ```
>
> **How thoroughly Red Hat enumerated decides whether absence is evidence, and that varies per
> CVE, not per identity class:**
>
> | CVE | known_affected | known_not_affected | reading |
> |---|---:|---:|---|
> | CVE-2026-42507 | 367 | 5 | thin — absence proves nothing → POSITIVE |
> | CVE-2024-45337 | 74 | 8,476 (incl. `ose-cli-artifacts`) | thorough — absence is meaningful → FALSE POSITIVE |
>
> Operative rule: assume vulnerable only when Red Hat lists our product as affected **and
> cleared nothing under that same parent product**. The parent restriction is load-bearing —
> `_pid_in_scope` deliberately admits any product carrying the workload's RHEL major (§8a), so
> a plain in-scope sweep for an OCP 4.12 / RHEL 8 image returns 521 clears of which **490 are
> RHACM, MCE, RHACS and GitOps** — products that are not ours and whose clears say nothing
> about us.
>
> This applies to the **non-RPM** path only. Red Hat enumerates rpms exhaustively (§9.1), so an
> absent rpm remains meaningful absence and stays a FALSE POSITIVE.

**Per-build corollary (images):** a `fixed` PID whose digest is not ours names another build,
and digests cannot be ordered — compare **Brew build stamps** (the purl `tag=` timestamp/epoch
vs this build's `version`-`release` labels): ours ≥ newest fix → the rebuild carries the fix
(not a "previous version") → FALSE POSITIVE; ours older → POSITIVE. A digest-less generic
`fixed` PID clears the stream outright.

---

## 6. Stream & Version Semantics (RPM)

### 6a. Backport model
Red Hat backports one CVE fix to multiple minor streams at **different upstream versions**.
Spot-check #2 (CVE-2020-11023, pkg `cpp`): `el9_0` fixed at `11.2.1-9.5.el9_0`, `el9_2` at
`11.3.1-4.4.el9_2`, `el9_4` at `11.4.1-4.el9_4`, `el9_5` at `11.5.0-5.el9_5`. A naive "installed
< some-fix" comparison is wrong across streams — the correct fix depends on the installed stream.

### 6b. Validated comparison algorithm
1. Detect installed minor stream from the `.el<N>_<M>` (or `module+el<N>.<M>`) marker.
2. If installed has a minor stream → compare **only** against `fixed` NEVRAs of the **same**
   minor stream.
3. If a fix exists but **not in the installed stream yet** → **still vulnerable** (POSITIVE,
   "No fix in el<N>_<M>; fix in other streams: …").
   - **Exception — strictly newer upstream version.** No erratum exists for our stream when our
     stream never needed one. Release numbers are branch-local and must not be compared across
     streams (`expat-2.5.0-6.el9_8.1` vs the 9.0 E4S backport `2.2.10-12.el9_0.4` reads 6 < 12 and
     calls the newer branch older), but the upstream **VERSION** carries no such confound: a build
     strictly greater on `EPOCH:VERSION` alone than *every* listed fix cannot be missing that fix.
     That case clears (FALSE POSITIVE). Equal versions differing only in release keep the confound
     and stay POSITIVE. Measured on `web-terminal-tooling-rhel9`: of 346 rows in this branch, 156
     were strictly newer on version, 190 tied on version — so the exception is deliberately narrow.
4. If installed has **no** minor marker (GA package) → it must be `>=` **all** stream fixes
   (a newer-stream fix proves the GA baseline is still vulnerable).
5. Compare with epoch-aware RPM vercmp; missing epoch propagated (§6e).
   Result: installed `>=` fix → FALSE POSITIVE; installed `<` fix → POSITIVE.
- Reference fix preference: when multiple in-scope fixes match, RHEL **base-repo** fixes are
  reported over add-on builds (e.g. AppStream `1.26.19-3.el9_8` over Ansible `2.7.0-1.el9ap`).

### 6c. Stream-aware `known_not_affected`
A KNA from a **different** minor stream does not clear the installed one (backport status differs
per stream) — the "scoped-clear" precision guard.

### 6d. Module streams
Parallel versions coexist (`perl:5.26` vs `perl:5.32`, `nodejs:18` vs `20`, `postgresql:12/13/15`).
A VEX PID with `::module:stream` matches only an installed **module** build (`.module+` in
release); a module PID never clears a non-module install and vice-versa. This guard is the root of the perl gap (§9).

### 6e. Epoch normalization
Version comparison parses `EPOCH:VER-REL`; higher epoch always wins; when the VEX fix omits the
epoch the RPM carries, it is propagated so the same-source packages compare correctly. Example epoch tokens seen: `0:` (dominant), `1:`,
`2:`, `3:`, `32:` (glibc), `15:` (dnsmasq/…).

---

## 7. Scanner-Side Model (RHACS)

SAMPLED — 766 distinct images of 13,745 (250 quay art-dev, 500 registry.redhat.io,
13 registry.access.redhat.com, 2 docker.io, 1 quay-other) plus 52 SBOMs (24,241 packages,
avg 466/image). A scan file is
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
directly (assessed at image/RPM level); JAVA→VEX bare `artifact` (strip the `group:` prefix);
NODEJS empty version → name-only match.

### 7b. Image-identity pseudo-components (SOURCE=OS, name contains `/`)
The scanner emits the **image's own identity** as OS pseudo-components. The `name` is the **image
path** (`namespace/image[-rhelN][-operator]`); the buildinfo path is the **location**, not the name
(`name` literally ending in `labels.json`: 0 occurrences — correcting a common misreading). Two forms:

| Location | Count | `name` example | `version` example | Version meaning |
|---|---:|---|---|---|
| `root/buildinfo/labels.json` | 4,575 | `openshift/openshift-enterprise-base-rhel9` | `1765773350` | epoch-seconds build time |
| `root/buildinfo/Dockerfile-<ns>-<img>-<NVR>` | 434 | `3scale-amp2/3scale-rhel7-operator` | `1.16.5-2` | Brew NVR-style |

These carry the `-rhelN` variant and the image namespace — any `/`-containing component belongs
to the non-RPM image path (§8) and is used for identity, never RPM version compare.

### 7c. Image labels (`metadata.v1.labels`) — presence in 766 images
`name` 762 · `com.redhat.component` 762 · `release` 762 · `version` 762 · `architecture` 762 ·
`vcs-ref` 762 · **`cpe` 608** · `io.openshift.build.commit.id` 357 · `io.openshift.release.operator`
87 · `org.jboss.product` 32. (So `com.redhat.component` and `cpe` are both real, present in
99% / 79% of images.) Example triple:
`name=openshift/ose-network-metrics-daemon-rhel9`, `cpe=cpe:/a:redhat:openshift:4.20::el9`,
`fullName=quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:29a8…`.

- **`version`/`release` = this build's coordinates** — the scanner-side half of the §5g
  build-stamp comparison. Two observed shapes: Brew NVR-style (`version=v4.12.0`,
  `release=202509030106.p2.g…` — YYYYMMDDHHMM timestamp) and Konflux-era
  (`version` may be junk, literally `"."`; `release` is **epoch seconds**, `1781806438`).
- **OCP minor derivation ladder** (digest pulls carry no tag): image-ref tag `v4.x` →
  CPE label version token → `version` label `v?(4.N)`. Without it, versioned stream parents
  ("Red Hat OpenShift Container Platform 4.15") cannot be scoped.

### 7d. Label-namespace ≠ registry-path-namespace (measured)
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
- **Reconciliation with the previously reported "139/747" (18.6%):** the *rate* matches the
  **published-only, art-dev-excluded** cut — measured 18.1% (88/486); an independent
  registry.redhat.io-only probe gave 17.4% (110/631). So the reference figure **excludes art-dev**
  (whose registry path is the meaningless shared `openshift-release-dev`, making its 45.8%
  all-image rate an artifact). The denominators differ by sample composition; the ~18% rate is
  the reproduced evidence.
- **Operational rule (holds regardless of the exact count):** the registry pull path is
  authoritative for the RHEL variant, the `name` label is secondary — bridged by OCI purl
  name-equality.
- **Stale `rhelN` labels:** sharper test = label's `-rhelN` ≠ actual base OS from
  `scan.operatingSystem` → **8/718** genuinely stale (e.g. `compliance/openshift-compliance-must-
  gather-rhel8` label says rhel8 but OS is `rhel:9`, path even says `-rhel9`). Re-derive the RHEL
  major from the pull path; it overrides the stale label.

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
- **`GENERATED_FROM`** = binary-RPM → source-RPM (the binary→source alias source):
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
all validated rules.

### 8a. Scoping predicate — evaluated for *every* candidate PID first
A PID is in scope for the workload iff:
- **UBI/RHEL:** PID is a RHEL base repo of the workload's RHEL major (derived from product-tree
  names starting "Red Hat Enterprise Linux" — no hardcoded stream list).
- **OCP:** RHEL base repos **+** any parent whose name is "Red Hat OpenShift Container Platform
  `<v>`", version prefix-matched (VEX `4` covers all `4.x`; `4.21` matches only `4.21.x`) **+** CPE
  prefix match of the image-label CPE against the VEX parent CPE **+** any product mentioning the
  workload's RHEL major (catches Fast Datapath etc.).
- **Operator:** RHEL base repos **+** catalog prefixes **+** a dynamic namespace map
  (registry-namespace → VEX product, built from the OCI purls in the product tree).

### 8b. The ordered ladder (first decisive rung wins)
| # | Rung | Condition (in scope unless noted) | Verdict |
|---|---|---|---|
| 1 | **Vendor catch-all** | `red_hat_products` (or any bare `cpe:/a:redhat` node) ∈ `known_not_affected`/not-affected flag | **FALSE POSITIVE** "No supported Red Hat product affected" |
| 2 | **Our-digest override** | any PID contains the scanned image's exact `@sha256:` digest | authoritative per-build: KA/UI→**POSITIVE**, KNA/fixed→**FALSE POSITIVE** (applies to RPM *and* non-RPM) |
| 3a | **Image identity via OCI purl** | image candidates {ref-repo (authoritative), `name`-label repo (secondary)} match a VEX OCI purl by exact `repository_url`, else by `pkg:oci/<name>` equality | matched generic image PID → POSITIVE/FALSE POSITIVE |
| 3b | **Image identity via path/generic** | image-path PID normalized (`ose-etcd-rhel9`→`etcd`) == OCP component; or generic `pkg:generic/redhat/<c>` (rhcos↔rhel-coreos) | same |
| 4 | **Same-image other-build evidence** | matched image PIDs for *other* builds, scored by RHEL-variant quality (exact `-rhelN`=2, version-neutral=1, other RHEL=0); SHA-exact (spec=2) overrides generic (spec=1); at equal quality, affected wins; other-build **fixed** digests decide by **build-stamp comparison** (§5g corollary: purl `tag=` vs this build's version-release) | POSITIVE / FALSE POSITIVE / POSITIVE (other-RHEL evidence, flagged) |
| 5 | **Component NEVRA/name in-scope** (RPM path) | package name ∈ names-to-match; dist-tag + minor-stream + module-stream + CPE scoping; then §6 version compare | KNA→FP; fixed→compare; KA→POSITIVE; UI→POSITIVE |
| 5s | **src-alias expansion** | binary comp aliased to source name when a `.src` PID's VR == installed VR **or** a version-less `.src` exists; also Maven `group:artifact`→`artifact`, SBOM binary→source. Within a status, a PID naming the component **exactly** outranks alias matches — a package with its own SRPM/statement is decisive over its alias source (`openssl-fips-provider` vs `openssl`) | expands names-to-match for rung 5 |
| 6 | **Product-family clear** (non-RPM fallthrough) | all in-scope PIDs for this CVE are `known_not_affected`/`fixed`, none affected/UI (in-scope UI alone → POSITIVE "under_investigation") | **FALSE POSITIVE** "no affected entry" (scoped-clear) |
| 7 | **Errata policy** (version-streams) | no direct match, but versioned OCP/RHOSE `fixed` streams exist: installed **older** than newest fix → assumed vulnerable; **equal/newer** → not | POSITIVE / FALSE POSITIVE |
| 8 | **Related-products evidence** | same package **named** in out-of-scope products marked with the workload's RHEL major **or** version-neutral PIDs (no el/rhel marker) | any affected→POSITIVE (conservative); clear-only carries no claim about our product → falls through to rung 9 |
| 9 | **Not listed** | no statement names this component/image/product anywhere relevant — in-scope affected rows (if any) name *other* components only (§5g: the errata assumption covers only *listed* products) | **FALSE POSITIVE** "not listed as affected" |
| 9r | **Truly absent** (RPM path) | RPM component name absent from the entire file, no related-product mention either | **FALSE POSITIVE** "not listed as affected" (same §5g logic as rung 9: the enumeration exists and does not name it) |
| 10 | **No VEX file** | Red Hat has not published a VEX for the CVE — no enumeration exists to be absent from | **POSITIVE** "VEX file missing" (severity/state Unknown) |

**RPM vs non-RPM split** happens after rungs 1-2: a `/` in the component
name (RHACS image-identity pseudo-component) **or** absence of an `.elN` marker routes to the
non-RPM path (rungs 3,4,6,7,8,9); an `.elN` marker or `SOURCE=OS` routes to the RPM path
(rungs 5,5s, then 8,9). Rungs 1,2 precede both.

### 8b-bis. Do NOT loosen image-name matching (2026-08-05)

Exact `repository_url` / `pkg:oci/<name>` equality is correct as written; normalising names
(stripping `-rhelN` or an `ose-` prefix) or matching on `com.redhat.component` manufactures
**cross-product** false matches:

- `registry.redhat.io/amq-streams/console-rhel9-operator` normalises onto VEX's
  `ose-console-rhel9-operator`, which belongs to `openshift4`. VEX has **zero** repos under
  `amq-streams` — that image is genuinely untracked and 0 matches is the right answer.
- VEX's `console-api` belongs to `rhacm2`, not amq-streams.
- `com.redhat.component` is `ubi8-container` for the StackRox `collector` image; matching on it
  would attribute base-image assessments to the product.

Of 337 images matching by no route at all, **249 are genuinely untracked by Red Hat**; the
other 88 are collisions of this kind. Silence is the correct output for both.

**Identity-route availability is thin for OCP payload images.** Across 13,136 RHACS scans
(2,932,234 findings): 27.2% of findings have the `name` label as their *only* identity route,
and 7.6% have none. VEX names the **published** `registry.redhat.io` digest, never the
`ocp-v4.0-art-dev` pre-release one, so for payload images the digest route and the registry-path
route are both structurally dead (0 of 201 sampled) — the `name` label carries them alone, on a
population where label and path namespaces disagree 67.3% of the time.

### 8c. Scanner-identity × VEX-identity pairings (every observed pairing + resolution)
| Scanner side | VEX side it matches | Rung |
|---|---|---|
| image digest (`@sha256:` in `image_ref`) | `stream:img@sha256:X_arch` PID with same X | 2 |
| image ref repo / `name` label | OCI purl `repository_url=` / `pkg:oci/<name>` | 3a |
| `ocp_component` (from name label) | image-path PID `ose-<c>-rhelN` / generic `<c>` | 3b/4 |
| RPM binary name + `.elN_M` version (`SOURCE=OS`) | `parent:name-E:ver-rel.elN_M.arch` in scope | 5 |
| RPM binary subpackage (`perl-libs`, `ceph-mon`) | source `.src` PID (`perl`,`ceph`) via alias | 5s |
| Maven `group:artifact` (`SOURCE=JAVA`) | bare `artifact` PID (`pkg:maven`) | 5s |
| Go module path (`SOURCE=GO`) | *(never tracked directly)* → containing image, else not listed | 3/6/9 |
| any component, family assessed clear | in-scope KNA/fixed only | 6 |
| OCP version vs RHOSE-`4.x` fixed streams | version comparison per errata policy | 7 |
| component in related RHEL-N / version-neutral product | out-of-scope KA/fixed/KNA | 8 |
| component/image unlisted (statements name others only) | — | 9 |
| RPM name absent from the entire file | — | 9r |

### 8d. Severity, state, and fix version come from the DECISIVE PID
Once a rung fires, severity/state/fix are read from **that** PID's `threats`/`remediations`, not the
document header:
- **Severity** priority chain: (1) OCI-purl-matched
  PID's impact — within this, **own digest > generic (no-digest) > other builds only if uniform**;
  (2) image-level PID impact; (3) component-name PID impact; (4) in-scope KA/fixed impact (highest);
  (5) `aggregate_severity`; (6) any impact threat; (7) CVSS `baseSeverity`; (8) RHACS scan severity.
- **State/justification**: from the decisive PID's remediation
  `details` — `no_fix_planned`→"Will not fix"/"Out of support scope"; `none_available`→"Fix
  deferred"/"Affected". **Never borrow another package's remediation**: "Will not fix"/"Fix
  deferred" are package-specific plans — a component with its own statement reads its own
  (`openssl-fips-provider` = Affected even though `openssl` = Will not fix in the same file).
  Not-listed FALSE POSITIVES carry "Not affected"; a missing VEX file → "Unknown".
- **Fix version:** the matched `fixed` NEVRA, preferring RHEL **base-repo** references over add-on
  builds.

---

## 9. Open Questions / Ambiguities

1. **perl-libs "src-alias failure" — investigated; it does NOT fail in current data, and the
   cause is not the src-alias** (verified against raw VEX JSON, live verdicts, and
   real-scan greps). Findings:
   - The perl `.src` PID is **not** shaped abnormally
     (`AppStream-8.10.0.Z.MAIN.EUS:perl-4:5.32.1-474.module+el8.10.0+24099+8aa2f756.src::perl:5.32`).
   - Red Hat VEX **enumerates every perl binary subpackage** per arch — `perl-libs` appears as its
     own NEVRA (48-108 per-arch entries in CVE-2026-48962 / CVE-2023-47038) — so `perl-libs` matches
     **directly**; the src-alias is never exercised. Live verdicts confirm it works: installed
     older → POSITIVE ("< fix 5.32.1-474…"), installed ≥ fix → FALSE POSITIVE.
   - **Version schemes align on both sides**, so no guard misfires in practice: **el9 perl is
     un-modularized** (plain `.el9` — sampled scans show `perl-Exporter 5.74-461.el9` etc.; VEX PIDs
     are plain `perl-4:5.32.1-481.el9`, no `::`), while **el8 perl is a module** (`.module+el8…` on
     both the RPM release *and* the VEX `::perl:5.XX` PID). Sampled scans: **8,038 plain vs 43 module**
     perl RPMs, and el8 module RPMs always carry `.module+` — so both sides agree.
   - **Two latent fragilities — both resolved (2026-07-14):** (a) the module-stream guard (§6d)
     used to skip every module PID when the installed release lacked `.module+` (a scanner
     normalizing the release away → rung 9 not-listed, a real statement dropped to silence).
     **Fixed**: `_module_stream_compatible` now falls back to structure — a numeric stream
     (`perl:5.32`, `nodejs:18`) must version-prefix the installed version and the RHEL major must
     agree; non-numeric streams (`container-tools:rhel8`) stay incompatible (nothing to verify).
     Covered by `tests/test_module_streams.py` (marker-stripped `perl-libs 472.el8_10` → POSITIVE
     via version compare; `474` → FALSE POSITIVE via KNA; equal-release-but-stripped stays
     conservative POSITIVE — a stripped release cannot *prove* it is the fixed module build).
     (b) the src-alias VR-equality gate was re-investigated and **retained deliberately**: dropping
     it misattributes an interpreter's fixed NEVRA to unrelated module packages sharing its dash
     prefix (`python3-urllib3` vs `python3`, `nodejs-nodemon` vs `nodejs`). The authoritative
     binary→source map is the SBOM's GENERATED_FROM (applied in `_resolve_comp`); the VR-equality
     `.src` alias is only the fallback when no SBOM is loaded.
2. **Dist-tag ≠ product.** `el9`/`el8` appear under RHOSE, RHEL base, and layered products alike
   (§2). Scoping must use the **parent PID**, not the dist-tag alone. `el9fdp`/`el9cp`/`el8ost`
   live under *both* their dedicated product (`9Base-Fast-Datapath`) and OpenShift/OSP streams —
   a component can be in scope via more than one parent.
3. **Namespace ambiguity.** One registry namespace can map to several VEX parent
   products; the namespace map is built per-CVE from OCI purls, so scope can vary by file. Undocumented
   namespaces fall back to purl package-name equality (§4a) — silent miss if neither matches.
4. **Version-neutral admissibility.** `red_hat_openshift_container_platform_4:openshift-clients`
   (no el/rhel marker) is admitted as related evidence because it "cannot contradict" the RHEL
   version — but it also cannot *confirm* the minor stream, so rung 8 verdicts on it are deliberately
   conservative, occasionally over-flagging.
5. **`fixed` without version verification (non-RPM).** For a non-RPM component where only a generic
   `fixed` PID matches (no digest, no version to compare), the verdict is POSITIVE ("fix exists;
   installed not verified") — conservative, may over-report already-patched builds.
6. **Registry-URL vs Brew-path PIDs.** Newer layered products use full
   `registry.redhat.io/<ns>/<img>@sha256` PIDs (§3b) while OCP core uses Brew `openshift4/<img>`
   paths; both must be parsed for the same image and treated uniformly via the
   OCI purl, which is present on both.
7. **Arch vocabulary mismatch.** Digests use `amd64/arm64`; NEVRAs use `x86_64/aarch64`. Any
   cross-identity arch reasoning must translate (or sidestep it by ignoring the digest
   arch suffix).
8. **Under-investigation is rare (146 files) but load-bearing:** always treated as POSITIVE; a
   later regeneration may flip it — verdicts are only as fresh as the mirrored VEX file.

---

## Appendix A — Validation: 5 hand spot-checks against raw JSON

Every count above was measured over the full corpus. These 5 rules are additionally verified by
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

## Appendix B — Methodology

All counts were produced by one-off mining passes over the full local mirrors: every
`data/vex/CVE-*.json` parsed for product-tree shapes, dist-tags, purl/CPE structure, and
statement vocabulary (§1–§6); scanner-side facts sampled from `data/scans/` and `data/sbom/`
(§7, sample sizes stated inline). Spot-check CVEs in Appendix A were selected by searching the
corpus for minimal files exhibiting each rule, then quoted verbatim from the raw JSON. Re-run
by re-measuring the mirrors — counts will drift as Red Hat regenerates VEX files daily.


