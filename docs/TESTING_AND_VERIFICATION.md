# Testing, Verification & Empirical Findings Report

This document records the complete multi-phase testing and verification history used to build and harden the `building-edgeconnect-preconfig-templates` skill across Orchestrator releases `9.6.4`, `9.7.1`, and `10.0.0` and appliance software versions `9.3.7` through `9.7.2`.

---

## Executive Summary

| Verification Phase | Scope | Volume Tested | Final Result |
|---|---|---|---|
| **1. Validator Behavioral Probes (`probes.py`)** | Synthetic `/validate` boundary & object-existence probes | `20` targeted probes | `20 / 20` behaviors characterized (`0` writes) |
| **2. 41-Section Option & Mutation Suite (`suite.py`)** | Every documented enum, range, and boolean option across all 41 sections of the default template | `473` option & mutation tests | `452` validated as expected; `21` vendor comment-vs-YAML drifts documented |
| **3. Multi-Orchestrator Read-Only Corpus (`corpus.py`)** | Real appliances across 4 Orchestrators (`9.6.4`, `9.7.1`, `10.0.0`) and 6 models (`EC-V`, `EC-US`, `EC-XS`, `EC-S`, `EC-10104/10106/10108`) | `65` captured appliances (`45` before the audit) | **`65 / 65` (`100%`)** pass translation, mutation, and `/validate` (rerun 2026-10-17) |
| **4. Closed-Loop Feature Testbeds (Batches `0`–`9`)** | Purpose-built lab topologies on 5 KVM `EC-V` appliances (Dual-WAN, MPLS bridge, EdgeHA bridge, Multi-VRF, ZTP discovery onboarding, ECOS `9.7.1` sections) | `10` multi-section batches (`31` non-hardware sections) | **`10 / 10` (`100%`)** applied & re-captured with **`0` mismatches, `0` missing leaves** |
| **5. Round 1 Live Apply & Diff Cohort (`25` Appliances)** | 25 diverse reference appliances (8 Hubs, 2 EdgeHA peers, 15 Branches) converted to Jinja2 + CSV, adapted, applied to lab appliances, re-captured, and diffed | `25` live appliance applies (`2,778` leaf values) | **`25 / 25` (`100%`)** `completionStatus=True`, **`2,778` matched, `0` mismatches, `0` missing** |
| **6. Round 2 Live Apply & Diff Cohort (`15` Appliances on ECOS `9.7.1`)** | 10 newly captured appliances (ECOS `9.3.7`–`9.7.2`) + 5 multi-feature appliances applied to an ECOS `9.7.1` lab appliance | `15` live appliance applies (`1,747` leaf values) | **`15 / 15` (`100%`)** `completionStatus=True`, **`1,747` matched, `0` mismatches, `0` missing** |
| **7. Offline Unit & Regression Suite (`unittest`)** | Secret redaction, GET-only enforcement, YAML 1.2 scalar parsing, Jinja/CSV round-trip, partial-batch validation, conflict-skipping upload, release payload gaps found by the audit below | run `python3 -m unittest discover -s tests` for the current count (`341` at 1.3.3) | all passing (1.3.3, 2026-10-31) |
| **8. Independent Audit (2026-10-17)** | Static audit of every script, rerun of phases 1–3, corpus extended from `45` to `65` appliances, live closed loop of every section that was `/validate`-only | `32` defects fixed, each with a regression test | See [Independent Audit](#independent-audit-2026-10-17) |

---

## Phase 1: Validator Behavioral Probing (`probes.py`)

Before writing section mappers, we built `tests/harnesses/probes.py` to test what `POST /gms/appliance/preconfiguration/validate` actually checks rather than trusting Swagger descriptions.

### Key Findings from Phase 1
1. **`/validate` checks live Orchestrator object inventories, not just YAML schema:**
   - The default template downloaded from `GET /gms/appliance/preconfiguration/default` is **rejected as-is** by `/validate` on the same Orchestrator if any example overlay (`CriticalApps`, `BulkApps`), template group, appliance group, interface label, segment, or zone does not exist on that Orchestrator.
2. **Release-specific schema enforcement:**
   - Sending a `9.6.4` default template to a `9.7.1` validator fails on `Unrecognized field: "address"` (under `nac.server[]`, which changed from `address` in `9.6.4` to `host` in `9.7.1`).
   - Sending a `10.0.0` default template to a `9.7.1` validator fails on `Unrecognized field: "ikePqcgroup"` (post-quantum IKE/IPsec fields added in `10.0.0`).
3. **Minimal valid document:**
   - `applianceInfo: {hostname: test-pcfg-probe}` (or even `applianceInfo: {}` without `hostname`) is accepted by `/validate`.

---

## Phase 2: 41-Section Option & Mutation Suite (`suite.py`)

We built `tests/harnesses/suite.py` and `scripts/options.py` to parse every `# Value: [...]` comment block across all 41 sections of the default preconfig template, generate a Jinja2 + CSV template per section, and test every documented enum value, integer minimum/maximum, and out-of-range negative value (`473` tests total).

### Key Findings from Phase 2
1. **21 Comment-vs-YAML Key Drifts in Vendor Default Templates:**
   - In `21` places, the comment block in the vendor's default template names a key that does **not** match the actual YAML key accepted by `/validate`:
     - `inboundPortForwarding`: comments say `wanInterface`, `destIp`, `destPort`, `targetIp`, `targetPort`, while the YAML keys are `sourceInterface`, `destinationIpSubnet`, `destinationPortRange`, `translateIp`, `translatePortRange`.
     - `nac.applyPolicies`: comment says `interface`, while the YAML key is `auth_interface`.
     - `ipSlaRule`: comment says `enableRule`, while the YAML key is `enable`.
     - `tunnelConfiguration`: comment lists `ikeEncryptAlgorithm: auto`, which `/validate` rejects (`ikeEncryptAlgorithm is invalid: auto`).
   - **Rule learned:** Always derive preconfig field names from the uncommented/commented YAML structure of the default template, never from prose descriptions in comments.
2. **Cross-Field Companion Constraints (`references/known-constraints.yaml`):**
   - Mutating a single CSV column can violate sibling constraints enforced by `/validate`:
     - `ospfSystemConfig.interfaces[].authentication: Text` requires non-empty `authenticationKey`; `MD5` requires non-empty `md5Password`.
     - `ikeConfig.ikeEncryptAlgorithm: aes128gcm16` requires `ikeAuthAlgorithm: "null"`, `ikePrf: prfsha256`, and `ikeVersion: 2`.
     - `ipsecConfig.ipsecEncryptAlgorithm: aes128gcm16` / `aes256gcm16` requires `ipsecAuthAlgorithm: "null"`.
     - `portForwardingRules[].destinationProtocol: icmp` requires `destinationPortRange: "0"` and `translatePortRange: "0"`; `any` requires `"0-65535"`.
     - `deploymentInfo.dhcpInfo[].option82SubOptions5` and `option82SubOptions150` cannot both be `"true"`.

---

## Phase 3: 45-Appliance Multi-Orchestrator Corpus (`corpus.py`)

We captured `45` real appliances (read-only `GET`) across 4 Orchestrators (`9.6.4.40046`, `9.7.1.42046`, `10.0.0.40516`), covering:
- **Appliance models:** `EC-V`, `EC-US`, `EC-XS`, `EC-S`, `EC-10104`, `EC-10106`, `EC-10108`
- **Appliance ECOS versions:** `9.3.7.0`, `9.5.7.0`, `9.6.2.0`, `9.6.2.1`, `9.6.4.1`, `9.7.0.0`, `9.7.1.0`, `9.7.2.0`
- **38 of 41 preconfig sections** populated from real appliance data (the remaining 3 — `poE` and `usblte` (hardware-only) and `availabilityTimeSettings` (business hours, readable only through a POST, so never captured) — verified via `suite.py` and `include_from_default`).

### Key Findings from Phase 3
1. **YAML 1.1 Scalar Corruption (`1:1`, `yes`/`no`, `08034`):**
   - Standard YAML 1.1 (`yaml.safe_load`) parsed BGP route target `"1:1"` as base-60 integer `61`, parsed strings `"yes"`/`"no"`/`"on"`/`"off"` as booleans, and crashed on New Jersey ZIP code `"08034"` (`ValueError: invalid literal for int() with base 8: '08034'`).
   - **Fix:** Implemented a strict YAML 1.2 Core Schema loader in `common.parse_yaml` restricting booleans to `true`/`false` and integers to `^[-+]?(?:0|[1-9][0-9]*)$`.
2. **Pre-9.6 ECOS Schema Differences (`9.3.7` & `9.5.7`):**
   - Appliances running ECOS `9.3.x` and `9.5.x` omit `sysConfig.roles`, `applianceIPs[].role`, and `sysConfig.maxInBW` in `GET /deployment`.
   - Some WAN interfaces specify `maxBW: {"outbound": 50000}` without `inbound`.
   - **Fix:** Defaulted missing `roles` to `{}`/`0` and missing `maxBW.inbound` to `maxBW.outbound`.
3. **Orchestrator-Managed vs. User-Intent Objects (`gms_marked`):**
   - Overlay hubs, Zscaler/SSE service tunnels, and EdgeHA peers automatically create loopbacks (`lo20000`), passthrough tunnels, IP SLA rules (`System_Rule_*`), and port-forwarding rules (`comment: "HA rule"`) marked `gms_marked: true`.
   - **Fix:** All mappers skip `gms_marked` / `gmsMarked` objects and record them in `ledger.json` as `orchestrator-managed`.

---

## Phase 4: Closed-Loop Feature Verification on Lab Topology (Batches `0`–`9`)

Because `/validate` only checks YAML syntax and Orchestrator object names, we built the lab apply-and-diff tool (`apply_and_diff.py`, kept outside this repository since 1.2.0) and tested applying rendered preconfigurations onto a 5-appliance KVM `EC-V` lab (`0.NE`..`4.NE`) with:
- **NICs 1–3 (`br0`):** Trunked VLANs (`mgmt0` DHCP, `wan0.4000` DHCP at `100000`/`100000` Kbps, LAN VLAN subinterfaces `lan0.71`, `lan0.72`, `lan0.81`, `lan0.82`, `lan0.130`).
- **NIC 4 (`MPLS` bridge -> `wan1`):** Isolated L2 bridge for static MPLS underlay (`192.0.2.1/24`..`192.0.2.5/24`).
- **NIC 5 (`HA` bridge -> `lan1`):** Isolated L2 bridge for EdgeHA interconnect (`169.254.1.0/24`, VLANs `100`–`103`) and LACP/Bridge group testing (`blan0`, `slan0`).

Every batch ran the full closed loop: **Jinja2 + CSV -> Render YAML -> `/validate` -> Upload (`POST /gms/appliance/preconfiguration`) -> Apply (`POST .../apply` or `.../apply/discovered`) -> Poll every step -> Re-capture live appliance (`capture.py`) -> Re-translate (`translate.py`) -> Leaf-by-leaf diff (`compare_intended_vs_actual`)**.

| Batch | Target Appliance | Sections & Features Verified | Apply Steps | Post-Fix Leaf Diff |
|---|---|---|---|---|
| **Batch 0** | `2.NE` (`ECOS 9.6.2.1`) | Baseline idempotency (`applianceInfo`, `templateGroups`, `businessIntentOverlays`, `deploymentInfo`, `idsIpsConfig`) | `6 / 6` | **`46` matched, `0` mis, `0` miss** |
| **Batch 1** | `2.NE` (`ECOS 9.6.2.1`) | 15 sections: Dual-WAN (`wan0.4000` + `wan1`), DHCP `server` (static MAC reservation) + DHCP `relay` (Option 82), `localRoutes`, `bgpSystemConfig`, `ospfSystemConfig`, `vrrp`, `peerPriority`, `inboundPortForwarding`, `loopbackInterface`, `customApplianceTags`, `segmentBfdConfigs`, `natPools`, `idsIpsConfig` | `16 / 16` | **`191` matched, `0` mis, `0` miss** |
| **Batch 2** | `1.NE` (`ECOS 9.6.2.1`) | 12 sections: `ipSlaRule` (`ping`), `tunnelConfiguration` (`gre` + `ipsec`), `virtualTunnelInterface` (`vti1`), `branchNatMapsConfig` (1:1 subnet + port translation), `nac` (all 6 sub-lists), `secureWebServicesConfig`, `ipAllowList`, `idsIpsConfig` | `13 / 13` | **`202` matched, `0` mis, `0` miss** |
| **Batch 3** | `0.NE` (`ECOS 9.6.2.1`, Hub) | Multi-VRF (`Default`, `corp`, `guest_vrf`): `segmentLocalRoutes`, `segmentBgpSystems`, `segmentOspfConfig`, `segmentBfdConfigs` | `10 / 10` | **`154` matched, `0` mis, `0` miss** |
| **Batch 4** | `disc#28` -> `3.NE`, `disc#29` -> `4.NE` | Zero-Touch Provisioning onboarding of 2 unapproved appliances via `POST /gms/appliance/preconfiguration/apply/discovered` | `8 / 8` each | **`53` matched, `0` mis, `0` miss** (each) |
| **Batch 5** | `3.NE` + `4.NE` (`SITE-C`) | Full EdgeHA pair over `lan1` (`clusterProfile: "Profile [EdgeHA]"`, `deploymentInfo.haConfig` with `haInterfaceOrder: INET1,MPLS1,INET2,MPLS2`) | `6 / 6` each | **`75` matched, `0` mis, `0` miss** (each) |
| **Batch 6** | `2.NE` | Cross-Orchestrator retail store template (`ref-orch-a/2.NE`) adapted via CSV and applied | `8 / 8` | **`62` matched, `0` mis, `0` miss** |
| **Batch 7** | `2.NE` | Cross-Orchestrator SOHO branch template (`ref-orch-b/1989.NE`) adapted via CSV and applied | `10 / 10` | **`127` matched, `0` mis, `0` miss** |
| **Batch 8** | `1.NE` | `bridgeGroups` (`slan0` on `lan1`, MTU `1500`, `adminStatus: Up`) | `7 / 7` | **`45` matched, `0` mis, `0` miss** |
| **Batch 9** | `2.NE` (upgraded to `ECOS 9.7.1.0`) | ECOS `9.7.1` & L2/tunnel sections: `dhcpRemoteAddressPoolConfig`, `multicast` (PIM + IGMP), `vxlan` (`lo1` VTEP + `vniVrfMaps`), `flowRedirection` (`wan1` cluster peer), `linkAggregation` (`blan0` on `lan1`) | `12 / 12` | **`115` matched, `0` mis, `0` miss** |

---

## Phase 5 & Phase 6: Large-Scale Live Apply & Diff Cohorts (`25` + `15` Appliances)

To stress-test the pipeline against real-world configuration diversity, we ran two large cohorts from a multi-tenant reference Orchestrator (`10.0.0`) through the complete pipeline (`capture.py` -> `translate.py` -> `generate.py` -> CSV row adaptation -> `render.py` -> `/validate` -> `/apply` -> post-apply `capture.py` -> `translate.py` -> leaf-by-leaf diff):

1. **Round 1 Cohort (`25` Appliances):**
   - 8 Cloud/On-Prem Hubs (`AWS`, `Azure vWAN/ILB/ARS`, `Google Cloud`, `Regional-HO`), 2 EdgeHA peers (`Branch-HA-Peer-1` & `Branch-HA-Peer-2`), and 15 Branches (covering IPsec passthrough tunnels, 802.1X/RADIUS NAC + OSPF, VRRP + IP SLA + Branch NAT, 6× HTTP/HTTPS IP SLA rules, BGP + OSPF + NAT pools + Port Forwarding, and 3-VRF BGP + BFD + VRRP + OSPF).
   - **Result:** **`25 / 25` (`100%`)** completed apply with **`2,778` matched leaves, `0` mismatches, and `0` missing leaves**.
2. **Round 2 Cohort (`15` Appliances — `10` New + `5` Existing with `2.NE` on ECOS `9.7.1`):**
   - Added 10 newly captured appliances spanning ECOS `9.3.7` (`EC-10108`), `9.5.7` (`EC-XS`), `9.7.1`, and `9.7.2` (`EC-V`, `EC-S`, `EC-10104`), plus 5 multi-feature existing appliances with `dhcpRemoteAddressPoolConfig`, `multicast`, `vxlan`, `flowRedirection`, and `linkAggregation` enabled on `2.NE` (`ECOS 9.7.1.0`).
   - **Result:** **`15 / 15` (`100%`)** completed apply with **`1,747` matched leaves, `0` mismatches, and `0` missing leaves**.

---

## Independent Audit (2026-10-17)

An adversarial re-audit reran every suite instead of trusting the figures above, and read every script for crash paths on payloads from older and newer ECOS releases.

**Harness defects that had hidden failures:**
- `suite.py` read `known-constraints.yaml` from a path that no longer existed and silently loaded no rules, so 25 documented dependency rejects were reported as unexpected. It now fails loudly when the file is missing. Rerun: `473` tests, `452` as expected, `21` documented key drifts, `0` unexpected.
- `probes.py` P18 expected `accept` for the `9.6.4` default template on a `9.7.1` validator; the validator rejects it (`nac.server[].address`). Rerun: `20 / 20` as expected.
- `corpus.py` printed its table but cut off the list of failing appliances, and it took the newest capture folder even when that was a partial `capture.py --only` run.
- The corpus rerun showed two lab appliances failing `/validate` (NAC references to unlabelled or deleted interfaces), so the earlier `45 / 45` no longer held until the NAC fixes below.

**Batch and upload invariants:**
- `/validate` answers HTTP 500 for some documents (for example `nac` with an empty sub-list). That raised an exception and stopped `render.py`, `upload.py` and `check.py` mid-batch. A 5xx answer is now that row's rejection; only an unknown validator, 401/403 or network failure stops a batch.
- One rejected upload POST stopped the remaining uploads and lost `upload-report.json`. Each failure is now recorded as `upload-failed`, the other rows still upload, and the exit code is non-zero.

**Mapping defects (each has a regression test in `tests/test_mappers.py`):**
- `idsIpsConfig` always wrote `mode: Off`, which would switch IDS/IPS off on any appliance running it (replace section). The mode now comes from `GET /ids/state` (`disabled`/`ids`/`ips_lookaside`/`ips_inline`); an appliance in no list is ledgered as unresolved and the section is not written. All four modes are confirmed by live apply and re-read.
- `branchNatMapsConfig` wrote `0.0.0.0/0` (the validator requires `any`) and wrote a NAT pool key (`trans_src: "41"`) as `translateSourceIpSubnet`; it now writes `translateNatPoolID` as the pool's index in `natPools`.
- `nac`: `source_ip_interface` and `applyPolicies[].auth_interface` naming an unlabelled or deleted interface were rejected by `/validate`. Servers now fall back to `any`; such policies are dropped and the ids renumbered; both are ledgered.
- Dual-stack WAN `static_slaac` dropped the static IPv4 address and next hop.
- Translate aborted on null `sysConfig` lists, on DHCP relay without option-82 sub-option keys (ECOS < 9.5.1) and on DHCP servers without a gateway. Mappers crashed on BGP neighbours without `evpn` (ECOS < 9.4.1), non-numeric interface speeds and null NAC blocks.
- Integer cluster-profile ids never matched the string keys of `/cluster/profileMapping`; string placeholder VNIs (`"0"`, `"-1"`) were written; BFD on OSPF interfaces was lost without a ledger entry when OSPF moves into `segmentOspfConfig` (that section has no BFD field).
- Validation substitution (`synth.py`) now replaces an `idsIpsConfig.profile` missing on the validator by `Default_<same signature suffix>`.

**Live closed loop of the sections that were `/validate`-only** (lab Orchestrator `9.7.1`, lab appliances on ECOS `9.6.2.1` and `9.7.1`; apply, re-capture, re-translate, leaf-by-leaf diff; matched / mismatched / missing):

| Run | Result |
|---|---|
| IPv6 LAN with router advertisement prefixes, IPv6 static route, BGP, OSPF, VRRP | `213 / 0 / 0` |
| DHCP failover (`dhcpHA`) | `64 / 0 / 0` |
| `natPools` + `branchNatMapsConfig.translateNatPoolID` (with `deploymentInfo`) | `85 / 0 / 0` |
| `localRoutes` subnet-sharing settings | all six mapped settings match; the 19 legacy redistribution fields have no read source |
| `appExpressGroups` (test group on a labelled loopback) | `1 / 0 / 0`; an empty list does not remove the association |
| `idsIpsConfig` `IDS Only`, `IPS-Performant`, `IPS-Inline`, `Off` | `2 / 0 / 0` each; `/ids/state` followed every mode |
| `upload.py` 3-row CSV, dry run then `--approve` | conflict and invalid rows skipped (no `.yml` for the invalid row), valid row uploaded with a normalised serial, stored `configData` identical to the rendered file, all cleaned up |
| 5 new reference appliances adapted to the lab | `557` matched, `0` missing; the mismatches are the additive `businessIntentOverlays` step (5), `networkRole` unchanged on a managed appliance (1) and one unconfirmed `filterRoutesWithLocalASN` case |
| Full restore of two lab appliances | `259 / 0 / 0` and `339 / 0 / 0` |

**Defects found by the live loop (each fixed with a regression test):**
- `capture.py` reused Orchestrator-scope reads (`/ids/state`, AppExpress, template and overlay associations) from any capture of the last hour, so a re-capture after an apply saw the old state. Reuse is now opt-in (`--reuse-orchestrator-reads`) and recorded in `run.json`. Apply-and-diff results for Orchestrator-scope sections in phases 4–6 were read through this cache.
- A translated `localRoutes` block without its subnet-sharing settings reset them on apply (advertise local LAN off, metric `0`, local-ASN filter off). The diff in phases 4–6 only checks leaves the preconfig sets, so it could not see this. The settings are now read from `/systemInfo/system` `auto_subnet`.
- `dhcpHA` and `raInfo[].prefix_id` were not translated.
- A local route with an interface and no next hop was written and failed at apply; it is now ledgered and left out.
- `branchNatMapsConfig` without `deploymentInfo`, and any `<SECRET:...>` placeholder, pass `/validate` but fail at apply; `validate.validate_text` now rejects both before the Orchestrator is called.
- Harness: the post-apply re-capture crashed on a transient failure (now retried), and a single-segment section was reported missing when the appliance reads back the same values under `segment*` `Default`.

New apply-time rules are in `references/validate-behaviour.md` section 2 (rows 11–22) and `references/known-constraints.yaml`.

## Raw Config Round Trip (`raw_diff.py`, 2026-10-17)

`apply_and_diff.py` only re-reads the leaves the preconfig set, after translating them back to YAML, so a setting the converter never captured cannot show up as missing. `tests/harnesses/raw_diff.py` compares what the appliances hold instead: every appliance-scope endpoint of two `capture.py` runs, the CLI running-config of the newest backup, and where each appliance appears in Orchestrator-wide objects. The source's IPs, names and nePk are first rewritten to the clone's (`--map OLD=NEW` or `--map-file`); `DEFAULT_IGNORE` lists the values that differ between any two appliances, each with its reason, and `--ignore REGEX` adds run-specific ones. The exit code is 1 while anything still differs.

```
python3 tests/harnesses/raw_diff.py --source <capture dir of the original> --clone <capture dir of the clone> --map-file map.yaml --out <dir>
```

Trigger a backup of both appliances before capturing, or the running-config is stale, and re-capture a few minutes after the apply: Orchestrator keeps building tunnels and overlay state after the apply reports done.

The lab was wiped to a blank preconfig (management interface untouched), rebuilt with three overlay topologies (full mesh, hub and spoke, regional hubs in two regions), five template groups, address groups, service groups, custom applications, application groups and an AppExpress group, and then a branch and a hub were each cloned onto a fifth appliance as a new site:

| Run | `apply_and_diff.py` (YAML leaves) | `raw_diff.py` (raw values) | Real gaps |
|---|---|---|---|
| Branch clone | `344` matched, `0` missing | `9,069` matched | static route flags and comments, peer priority written beside its template, disabled segment instances dropped silently, per-segment add-local-ASN, appliance-side inter-segment security rules, NAC policy on a deleted interface (expected, `lessons.md` 13) |
| Hub clone | `335` matched, `0` missing | `8,116` matched | the same route gap, hub membership of overlays |

The YAML-level diff saw none of these. Fixed in the converter: route flags and comments (`static-routes-configured`), the `peerPriorityList` template, and ledger entries for disabled segment instances and hub membership. The other gaps have no preconfig field; they are in `references/lessons.md` 16–17. The one test design error found (two template groups setting DNS with no priority) is `lessons.md` 17.

## Variable Review Sheet (`variables.csv`)

- `tests/test_variables.py` pins the classifier rules, linked columns (a gateway equal to an interface address renders as `data['lan0_ip'].split('/')[0]` and follows it), owner edits (flip a field, rename a column), and the refusal of a bad or foreign sheet.
- Offline check on real captures: translate the latest capture of every appliance with the sheet it proposes, render `example.csv`, and compare. All 65 appliances translated; the example row reproduced `reference.yaml` (apart from secret columns, which are blank by design) and passed the flow-through check for every site; the 60 that were comparable kept a byte-identical `reference.yaml`. Columns per site fell from a median of 36 to 22 (2,688 to 1,548 in total, 66 of them shared columns).
- Not run: `/validate` or a lab apply of rows rendered from the new sheet. The YAML a row produces does not change, only which of its values are columns.

## Site Comparison (`translate.py --compare`)

- `tests/test_variables.py::Compare` pins the rules: a field that differs between the sites is a variable, one equal everywhere is fixed whatever its name, a field the others lack is fixed and flagged "different site type", and the site's own interface addresses stay columns.
- Offline run on 12 real captures, each compared with the next three captures in the folder (not chosen to be one site type, so this shows the mechanics, not how good the proposals are for a true set of branches): every run exited 0, the comparison sheets differ from the plain ones (more variables, many flagged rows where shapes differ), and the example row still reproduced `reference.yaml` and passed the flow-through check.
- Real same-shape sets (2026-10-19): the 65 latest captures fall into one group of 4 sites on one Orchestrator, two pairs (one from that Orchestrator, one from another) and singles. For each set the sheet from the first site was applied to every site and the shared template was rendered with each site's own row: the render reproduced each site's `reference.yaml` and passed the flow-through check for all 8 sites, with one exception that is not new (an empty-string `site` in one capture comes back as null). The first run of the 4-site set showed the group and the last template group differing between EMEA and APJ sites although both were fixed; they now become variables when the given sites differ.
- First `/validate` attempt on those sets (lab, 2026-10-19): the cell check wrongly rejected `behindNat: auto` at two sites, because the column's format was inferred from the template site's address; the default template allows `auto`, `none` or an address, so `cells.py` now accepts those two words there (`ADDRESS_OR_WORD`).
- DHCP interfaces (2026-10-19): the same pattern made an interface's address and next hop required or unchecked depending on the template site. On 65 real appliances there are 52 `dhcpv4`, 4 `slaac` and 1 `dhcpv6` WAN interfaces against 30 static ones. `/validate` on the lab accepted a `dhcpv4` interface with the address and next hop null, empty or left out, and rejected a `static` one with them empty (`ipAddressMask is required`). The format now comes from the field (`ipAddressMask`, `nextHop`), and the row's `addressingMode` (column or fixed) decides: static needs both, `dhcpv4`/`dhcpv6`/`slaac` needs them blank; a blank cell renders as null (`tests/test_cells.py::AddressingMode`).
- Lab (virtual lab, 2026-10-19, converter at the fix commit): `/validate` accepted 8 of 8 rows of the three sets once lab-only names were mapped (groups, case-sensitive regions, zone, WAN label). A clean-restore apply of the 4-site set (all hubs) completed on all four with no failed steps; after re-capture and re-translation everything pushed read back, apart from the overlay list order and three keys of the lab's own segments. One hub's raw diff has the same 2,720 differing leaves as the earlier direct-conversion run. The lab adapter replaces each site's WAN with the lab's own, so `behindNat: auto` was only `/validate`d (the rendered interface block was accepted), not applied live. Lab restored to its pre-test state afterwards.

## Command Line and Variable Ranking (1.2.0)

- `tests/harnesses/rank_variables.py` ranks every kind of setting by how often its value differs between two appliances of the same design (same Orchestrator, same network role), matching list items by name (`lan0.71`, a tunnel name) rather than position. On 2026-10-22 it read the newest capture of 60 appliances (the 5 KVM lab appliances left out, since tests rewrote them): 879 pairs, 144 settings with at least 5 appliances and 10 pairs. The top: LAN interface address, DHCP range and gateway, BGP and OSPF router IDs and management IP at 100%, location fields at 97-99%, template groups 97%, BGP ASN 96%, total bandwidths about 90%. A static WAN address ranks near 52% because most WANs in the corpus use DHCP. The output file holds setting kinds and percentages only, never values or names.
- `tests/test_cli.py` pins the CLI: the Top N ticks only ranked settings plus the site's own addresses, a gateway follows the interface address it copies (seen failing with that rule removed), the chosen sheet builds a template with exactly those columns, `compare` writes each site's own values into its row with serials and secrets blank, a non-validator Orchestrator stops `build` before any read, a build that fails validation keeps nothing, and the stage names still dispatch.
- Live (2026-10-22): `list` (then named `appliances`) against two Orchestrators read-only. `build` from a lab Orchestrator with validation there: the capture (GET) worked, and `POST .../preconfiguration/validate` answered HTTP 403, because that profile's API key is read-only and Orchestrator counts `/validate` as a write permission although nothing is saved. Nothing was kept, as designed; the run also found that the refusal printed a traceback, now a one-line error (`tests/test_cli.py::Dispatch`).
- Live on a 10.0 lab Orchestrator (10.0.0.40625, 2026-10-22, reads and `/validate` only, no upload): `list` listed and tested the profile; `build` of a cloud hub captured it (GET only, about 2.5 minutes), and `/validate` accepted the result; `variables --pick top10 --yes` built a 33-column site type whose example row was accepted; `validate` passed 1 of 1 rows; `compare` with two hubs of the same design found the 2 settings that differ besides the always-per-site ones and wrote `sites.csv` with a row per hub, and `/validate` accepted all 3 rows, each rendered with its own hub's values. The run found that Top 10 pre-ticked interface labels and zones (ranked high, but layout stays fixed unless flipped), fixed with a test.
- Upload on the virtual lab Orchestrator (9.7.1, 2026-10-22): `build` of its one reachable appliance (`/validate` accepted), then `upload` of one row without `--approve` (table only, 0 writes) and with it: uploaded, read back, no serial and `autoApply` off. Not applied, by the owner's choice.
- Refused reads (`docs/decisions/0009`): a 403 on one read is recorded as `denied` and capture continues; translate reports it as `not-readable` with the sections it feeds, and the verdict counts it (`tests/test_report.py`, seen failing on the old code). A 401 still stops.
- Review fixes (1.2.2, test first): Top 10/20 never tick template groups or overlays; `--pick all --yes` makes every setting per site; `compare` compares interface names directly (any name, not only lanN/wanN) and writes no row for a site whose names differ at the same position; a 403 on `/subnets` or `/subnets/all` stops the capture (`docs/decisions/0010`); a 403 on `/reachability/gms` is reported and the live reads still run; `list` prints its status line only after `/appliance` answered; `compare` writes `sites.csv` even when every other site is left out (the live run found it missing). Live on the virtual lab Orchestrator: `list`, `build`, `variables --pick top20` (no template-group column) and `--pick all` (238 columns), `compare` with a site of another layout (named in a note, no row, this site's row validated), `validate`.
- Exact validator names (1.2.3, test first, `docs/decisions/0011`): `tests/test_validators.py` pins that only nicknames listed in `EC_VALIDATORS` may run `/validate` (no `lab`/`vlab`/`test`/`sandbox` substring match, no built-in `lab`/`vlab` fallback) and that a refusal says to add the nickname to `EC_VALIDATORS` in `.env`; seen failing on the old code, which also allowed `prod_testbed` and `lab_prod`. `summary.md` no longer mentions `--refresh-skills`, which no command has (`tests/test_report.py`).
- Code out of the skill folder (1.3.0, test first, `docs/decisions/0012`): `toolkit/` is the only source and the skill ships a copy made by `tools/build_skill.py`. `tests/test_layout.py` fails while the copy or `dist/` differs from `toolkit/` (seen failing before the first build), and checks that the install folder's `preconfig-work/` is found from both layouts (seen failing on the old lookup, which looked two folders too high from `toolkit/`).
- ECOS 9.5 and the allow list (1.3.0, test first, `docs/decisions/0013`): a read-only 9.7.1 Orchestrator with 8 ECOS 9.5.2 appliances (EC-XS, EC-S) reproduced an outside tester's `/validate` error, `HTTP 400 Unrecognized field: "dot1x_acct_server_group"`, on 4 of 8. ECOS 9.5.x NAC `aaaProfile` carries two accounting keys no template has; the converter now writes only key paths in the target's default template plus `TEMPLATE_OMISSIONS`, one `outside-preconfig` ledger line per dropped path. The same run found 9.5.x leaving out `routeLabelId` (IP SLA) and `tracker` (VRRP), which crashed those mappers, HA groups with `v6HaMask: 0` (`/validate`: mask must be 1-127), a bonded `blan0` with empty speed reported as unresolved, and capture skipping live reads while Orchestrator reported reachability state 5 (sync in progress). `tests/test_mappers.py::Ecos95` and `tests/test_capture.py` pin each, all seen failing on the old code. Corpus run with `/validate` on the lab (83 appliances, names substituted): 75 accepted before, 79 after, all 8 of the 9.5 set accepted; no other appliance changed result or section count; toolkit errors 5 to 0. The 4 left are not converter faults: a 9.3.1 capture with no deployment data, the branch NAT subinterface guard, and two lab appliances whose template groups no longer exist on the lab Orchestrator. `TEMPLATE_OMISSIONS` holds the 10 key paths the corpus writes, the templates do not show, and `/validate` accepted.
- Release families (1.3.0, `docs/decisions/0014`): `tests/test_templates.py` pins the template choice (exact build; newest of the same major.minor; nearest older, marked untested; nearest newer; none only with an empty folder); the earlier test that a missing build stops translate now pins that only an empty template folder stops it. Live on a 9.5.2 HA appliance from a read-only 9.7.1 Orchestrator, with that Orchestrator's own 9.7.1.42060 template absent: `--target-release 9.7.1.42060` used 9.7.1.42046 (same family) and `--target-release 9.8.0.1000` used 9.7.1.42046 (nearest older, untested); `summary.md` and `ledger.json` named the template and why, and `/validate` on the lab accepted both.
- Downloaded templates (1.3.0, test first): `tests/test_capture.py::DefaultTemplateTest` pins that capture writes an Orchestrator's default template to the work folder's `reference/default-templates/` and that the bundled folder stays empty; it was seen failing on the old code, which wrote into the toolkit. Live: a GET-only capture from a read-only 9.7.1.42060 Orchestrator saved that release's template in the work folder, `toolkit/` and the skill copy stayed unchanged (`tools/build_skill.py --check` clean), and `translate --target-release 9.7.1.42060` used it as the exact template; `/validate` on the lab accepted the result.
- Lab replicate of a 9.5.2 set (1.3.0, test first): six designs from a read-only 9.7.1 Orchestrator were adapted to the virtual lab, uploaded and applied by the owner from the GUI, then re-captured and compared with the source leaf by leaf, on every endpoint and the CLI running-config. Five matched apart from template-owned, lab-adapter, hardware and version differences; the sixth source had no LAN addressing, so its deployment cannot be applied by any preconfig. Three converter fixes came out of it, each with a test seen failing on the old code: capture redaction no longer reaches across a line break when a CLI secret is empty (it replaced the first word of 6-8 following lines per appliance; fresh captures now have none), a segment whose OSPF is off but configured on interfaces is written with `enable: false`, and relay-interface lease times are ledgered as outside-preconfig. Corpus with `/validate` on the lab, same captures before and after: 81 accepted, 2 known non-passes, identical per appliance; the 8-appliance 9.5.2 set 8 of 8.
- No apply path (`tests/test_no_apply.py`): no script or test calls `/gms/appliance/preconfiguration/apply` or sets `autoApply` true, and `upload` has no `--auto-apply` (the scan was seen failing on a reintroduced `autoApply` line). The lab apply-and-diff tool behind the batches and cohorts above now lives outside this repository, behind two terminal gates; its guardrails and diff are `tests/harnesses/lab_diff.py` (`docs/decisions/0008`).
- Full CLI run on the virtual lab Orchestrator (9.7.1, 2026-10-22, 1.2.1): `--help`, `--version`, an unknown command, `list` with and without `--search`, the `EC_VALIDATORS` guard, an unknown appliance, a folder without `build.json`; `build` of four appliances (one reachable, two offline with Orchestrator's cache, all three accepted by `/validate`; the fourth offline with no cache now stops with one line instead of a traceback, and a stopped capture no longer leaves a half-written folder); `variables` with Top 10, Top 20 plus `--set` (an unknown name refused), `--yes` without `--pick` refused, and the tick list driven through All, a section, the locked list, the Top list, a search and a miss; `compare` with two other appliances (different designs: their rows failed the cell checks with each blank column named, as intended); `validate` with a bad address (row named and skipped); `upload` without and with `--approve` (uploaded with `autoApply` false) and again (conflict skipped); the stage forms `cache-check`, `validate` with files and `check --validate`. Test preconfigs deleted afterwards.
- RBAC on that Orchestrator: an API key with roles can call only the endpoints its roles' menus allow, and the appliance passthrough is filtered by the URL inside it. `/natMaps`, `/natAll` and `/gms/versions` needed menus that only roles created on older releases still carry, and `subnets3/configured` through `/appliance/rest` stayed refused even with every menu the 10.0 UI offers. `GET /rbac/allowedRestApis?method=GET` lists what a key may call.
- Dry run on real captures (2026-10-22, capture and `/validate` stubbed): `build`, `variables` (Top 10, search, sections) and `compare` with two other appliances ran end to end; the comparison flagged the three appliances as different designs, as they were.

## Offline Cell Checks (`cells.py`)

- `tests/test_cells.py` pins the checks (typo in an address, missing or extra prefix length, spaces, blank required cell, whole numbers, documented range, subnet membership) and the `render --site-dir` and `upload --csv` command lines.
- False-rejection check on real captures: `cell_problems` and `subnet_problems` run on the `example.csv` of all 65 appliances (338 address columns). The first run rejected two sites, a tunnel `maxBandwidth` of 0 against the documented range 1 to 10,000,000 (valid with auto bandwidth); a cell equal to the reference appliance's own value now always passes. After that, 0 of 65 rejected.
- Negative control on 63 appliances with an interface: moving one interface's address to another subnet flags the addresses that depended on it, and `198.18.99.300/24` is rejected.
- Not run: `/validate` or a lab apply; the checks only decide whether a row is sent.

## Raw Round Trips of Real Sites (PR #2, 2026-10-18 and 2026-10-19)

`raw_diff.py` round trips of real appliances (converted, applied to a blank lab appliance, re-captured, compared raw) ran through several passes and ended with a 30-site pass with no converter gaps (2026-10-19). The converter fixes they produced, each with a unit test:

- Routes: next hop `0.0.0.0`/`::` and `default`-interface routes read from the route's `config`; the zone taken from `config`; every `gms_marked` route skipped (Orchestrator-made, for example cloud load-balancer routes); route tags, flags and comments carried.
- Segments: every segment with routes or non-default subnet-sharing settings written, default-valued segments left out, and no empty route map written.
- Template groups: only the fields the `routes`, `bgp` and `vrrp` templates set are left out (`FIELD_TEMPLATES` in `translate.py`).
- NAC: trusted interfaces written as `auth_type: trusted`, LAN labels only, once per label, and not on the RADIUS server's source label.
- Tunnels: `esp ""` to `auto`, anti-replay `disable` to `0`, `secrecyGroup: disable` with PFS off; pre-`/validate` rejection of a short PSK, IKEv2 without identifiers and `no_encap` without `remoteIp`.
- Ledger only (no preconfig field): firewall rules Orchestrator did not push, business hours, hub membership of overlays.
- Other: secure web services kept when any value differs from the default, management routes and pass-through shaping read from the running config, IP SLA actions and probe sources, flow-redirection wait time 50 when the running config omits the line.

## Harness notes

- `tests/harnesses/scan.py --orchestrator <profile>` (GET only) writes `samples/<profile>/scan.json`: which catalogue endpoints return data per appliance, used to choose a varied corpus.
- The lab apply-and-diff tool (`lab_diff.check_guardrails`) refuses any Orchestrator profile whose name does not contain `vlab`, and any preconfig with `managementIp`.

## Catalogue of the 21 Bugs & Behavioral Rules Found Before PR #2

Every item below was caught by closed-loop testing and is now encoded in both the deterministic scripts (`scripts/`) and the agent references (`references/`):

1. **`firewallMode` (`harden`) Integer Codes (`0=All, 1=harden, 2=stateful, 3=statefulSNAT`):**
   - Vendor default template comments list `[All,stateful,statefulSNAT,harden]`, which is not in numeric order. Live apply proved `1` is `harden` and `2` is `stateful`.
2. **Multi-Segment Precedence (`segmentLocalRoutes`, `segmentBgpSystems`, `segmentOspfConfig`):**
   - When both `bgpSystemConfig` and `segmentBgpSystems` (or `localRoutes`/`segmentLocalRoutes`, `ospfSystemConfig`/`segmentOspfConfig`) appear in one YAML file, Orchestrator **silently ignores** the single-segment section during `/apply`. Mappers now emit all active segments (including `Default`) inside `segment*` whenever any non-Default segment is active.
3. **Branch NAT Maps Endpoint (`GET /nat/maps`, not `GET /natMaps`):**
   - `branchNatMapsConfig` is stored in `GET /nat/maps` (`branch-nat-maps`), whereas `GET /natMaps` is the legacy WAN NAT policy map. Also verified that `interfaceName` must be a LAN interface or `any` (WAN interfaces pass `/validate` but fail at `/apply`).
4. **DHCP Relay (`dhcpType: relay`) & DHCP Server Ranges/Options:**
   - Added full `dhcpd.type == "relay"` (including Option 82 policy and suboptions `1, 5, 10, 11, 150, 151, 152`) and `dhcpd.server` (`ip_range`, `options`, `host` static MAC assignments) mapping in `translate.py`.
5. **EdgeHA (`deploymentInfo.haConfig` & `applianceInfo.clusterProfile`):**
   - Reconstructed `clusterProfile` and `haConfig` (`haPeerSerial`, `haPeerHostname`, `haIpPool`, `haVlanStart`, `haInterface`, `haInterfaceOrder`, `haPeerInterfaceInfo`) from `/haGroups`, `/cluster/profileMapping`, `/appliance`, and `sysConfig.haIf` subinterfaces, while excluding auto-generated `haIf` subinterfaces from `deploymentInterfaces`.
6. **GRE Passthrough Tunnel Mode (`gre_ip` -> `gre`) & IKEv2 `identifierValue`:**
   - Applying `tunnelEncap: gre` stores `mode: "gre_ip"` in `/tunnels2/passThrough`; applying `ikeVersion: 2` copies `localIkeIdentifier` into `id_str`.
7. **`ipAllowList` Entries Have `gmsMarked: true`:**
   - Entries pushed via `ipAllowList` in a preconfig are marked `gmsMarked: true` on the appliance and must be included by `m_ipAllowList`.
8. **NAC `applyPolicies` Sequential IDs & `source_ip_interface` Label Resolution:**
   - `applyPolicies` IDs must be sequential `1..N` over active interfaces; `server[].source_ip_interface` and `applyPolicies[].auth_interface` must be distinct LAN interface labels.
9. **Canonical Ordering of `deploymentInterfaces` & Next-Hop 0.0.0.0 Routes:**
   - `/deployment` orders `lan` interfaces before `wan` interfaces and sorts VLAN IDs numerically. Routes in `/subnets` whose state has empty `nextHop` and `ifName` are next-hop `0.0.0.0` routes; their `config` holds the next hop and interface (see lessons item 4). Only `gms_marked` or config-less ones are skipped.
10. **Preserving `mgmt0` DHCP & Post-Onboarding Reachability (`state == 4`):**
    - When `mgmtIfData.mgmt0.dhcp` is `true`, `m_managementIp` omits `managementIp` even if the stored CLI backup contains `ip mgmt-ip <leased-ip>`. Newly onboarded appliances report `state == 4` in `/reachability/gms`.
11. **VRRP `description: null` & `authenticationString: null` Fail at `/apply`:**
    - `/validate` accepts `description: null`, but ECOS rejects it during `/apply` (`Binding is not of correct type... key: desc`). Mappers omit `description` and `authenticationString` when empty.
12. **All 4 `ipSlaRule` Monitor Types (`ping`, `interface`, `vrrp`, `http/https`) & Actions:**
    - Added mappings for `ip-monitor` (`ping`), `port-monitor` (`interface`), `vrrp-monitor` (`vrrp`), and `http-monitor` (`http/https` with `urls` and `httpRequestTimeout`), plus `modifySubnetMetric` and `defaultSubnetAction`.
13. **EdgeHA Auto-Generated Port Forwarding (`comment: "HA rule"`) & `flowRedirection` Sync Subinterface:**
    - Skipped EdgeHA-created UDP port-forwarding rules (`comment == "HA rule"`) and `cluster interface <haIf>.164` subinterfaces, ledgering both as `orchestrator-managed`.
14. **`inboundPortForwarding.sourceInterface` Numeric Label IDs & WAN Combo Ports (`lan2`):**
    - When `sourceInterface` is given a WAN label (`INET1`), the appliance stores the numeric label ID (`"2"`) in `srcIf`; `m_inboundPortForwarding` resolves numeric IDs via `ctx.label(srcIf)` and maps `lan*` WAN combo ports to their WAN label.
15. **IPsec Passthrough Tunnel `esp`:**
    - Applying `ipsecEncryptAlgorithm: "none"` stores `esp: "null"` and `"auto"` stores `esp: ""`; `m_tunnelConfiguration` maps `"null"` to `"none"` and `""` to `"auto"`, and writes `"null"` under `aes128gmac`/`aes256gmac` authentication (fixed 2026-10-18: `""` used to become `"none"` and cloned an encrypted tunnel unencrypted).
16. **Dual-Stack IPv4+IPv6 on VLAN Subinterfaces (`vlan > 0`):**
    - On ECOS `9.6.x`, dual-stack IPv4+IPv6 on a VLAN subinterface (`vlan > 0`) is ignored during `/apply`.
17. **Leading-Zero Numeric Strings in YAML 1.2 (`08034` ZIP Code):**
    - Restricted `tag:yaml.org,2002:int` in `common.parse_yaml` to `^[-+]?(?:0|[1-9][0-9]*)$` so leading-zero strings are never parsed as base-8 octal integers.
18. **Pre-9.6 ECOS (`9.3.7`, `9.5.7`) Missing `roles` / `maxInBW` & Partial WAN `maxBW`:**
    - Handled absent `sysConfig.roles`, `applianceIPs[].role`, `sysConfig.maxInBW`, and `maxBW.inbound` in `translate.py` and `mappers.py`.
19. **`GET /dhcpConfig/remoteSubnets` Includes Local Interface DHCP Pools:**
    - Filtered `/dhcpConfig/remoteSubnets` to `not p.get("interface")` so local `deploymentInfo.dhcpInfo` pools are never duplicated into `dhcpRemoteAddressPoolConfig`. Documented that `dhcpRemoteAddressPoolConfig` requires a running local DHCP server on the appliance.
20. **`multicast[].pim[].igmpEnable` Stored at `seg["igmp"][ifname]["enable"]`:**
    - Even when `igmpEnable: false`, the interface key is present in `seg["igmp"]` with `{"enable": false}`; updated `m_multicast` to read `bool(seg["igmp"].get(k, {}).get("enable"))`.
21. **Live JSON Readback for `vxlan` (`/vxlan/config` + `/vxlan/segVniMap`) and `flowRedirection` (`/cluster`):**
    - Updated `m_vxlan` and `m_flowRedirection` to read live JSON endpoints first, falling back to stored CLI backups only when an appliance is offline.
