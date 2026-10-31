# What `POST /gms/appliance/preconfiguration/validate` Checks vs. Does Not Check

Measured empirically via `tests/harnesses/probes.py` (probes), `tests/harnesses/suite.py` (option tests), `tests/harnesses/corpus.py` (real appliances), and closed-loop live `/apply` runs.

---

## 1. What `/validate` Checks (Orchestrator-Scope & Schema Checks)

`/validate` is a non-saving `POST` endpoint (`read_only=True`). It stops at the first error and verifies:
1. **YAML syntax & release schema:** Rejects unknown sections or fields (`YAML invalid, Unrecognized field: "..."`), including fields from older (`9.6.4` `nac.server[].address`) or newer (`10.0.0` `ikePqcgroup`, `ipsecPqcgroup`, `flowProcess`) Orchestrator releases.
2. **Scalar & collection types:** Verifies integers, booleans, enums, IP/subnet formats, and whether a section expects a mapping vs. a list (e.g., `dhcpRemoteAddressPoolConfig` must be a mapping, whereas `natPools` and `multicast` are lists). On `10.0.0`, `secureWebServicesConfig.urlClassificationConfig.flowProcess` must be present and boolean, else `Secure Web Services Config - Not valid value: flowProcess.` (the mapper writes the appliance's value or the default `true`).
3. **Serial number format (`serialNum`):** If provided in the top-level JSON wrapper, must be 12 hexadecimal characters (`^[0-9A-Fa-f]{12}$`, e.g., `001BBC462D3D` — hyphens/colons like `00-1B-BC-46-2D-3D` are rejected unless normalized first via `common.normalize_serial`).
4. **Live object existence on the validating Orchestrator:**
   - `applianceInfo.group` -> must exist in `GET /gms/group`
   - `applianceInfo.region` -> must exist in `GET /regions` (when non-null)
   - `applianceInfo.clusterProfile` -> must exist in `GET /cluster/profiles`
   - `templateGroups.groups` -> every name must exist in `GET /template/templateGroups`
   - `businessIntentOverlays.overlays` -> every name must exist in `GET /gms/overlays/config`
   - `interfaceLabel` (in `deploymentInterfaces`, `haPeerInterfaceInfo`, `loopbacks`, `vtis`, `inboundPortForwarding`, `ipSlaRule`, `nac`) -> must exist on the matching side (`lan` vs. `wan`) in `GET /gms/interfaceLabels`
   - `segment` (in `deploymentInterfaces`, `segmentLocalRoutes`, `segmentBgpSystems`, `segmentOspfConfig`, `segmentBfdConfigs`, `loopbacks`, `vtis`, `natPools`, `branchNatMapsConfig`, `inboundPortForwarding`, `vxlan`, `multicast`) -> must exist in `GET /vrf/config/segments`
   - `zone` (in `deploymentInterfaces`, `localRoutes`, `segmentLocalRoutes`, `loopbacks`, `vtis`, `vxlan`) -> must exist in `GET /zones`
   - `role` (in `deploymentInterfaces`, `loopbacks`, `vtis`, `vxlan`, `nac`) -> must exist in the Orchestrator's identity roles (`default`, etc.)
   - `appExpressGroups` (a plain list of group names; `[]` and null are accepted) -> every name must exist in `GET /applicationDefinition/appExpressGroup/config`, else `AppExpress groups must be created manually before applying.`
   - `idsIpsConfig.profile` -> must be a full profile name from `GET /ids/signatures/profiles` (suffix included, e.g. `Default_S7`), else `Ids/Ips Config - Not a valid Profile`
5. **Cross-field companion rules:** Enforces the rules in `references/known-constraints.yaml` (e.g., IKE/IPsec GCM/GMAC combinations, OSPF auth keys, ICMP port 0, `vxlan.vtepSrcInterface` format `lo0`..`lo99999`, `branchNatMapsConfig` equal subnet prefix lengths and non-overlapping ports).

---

## 2. What `/validate` Does NOT Check (Caught Only by `check.py` or Live `/apply`)

Passing `/validate` **never** guarantees that `POST /gms/appliance/preconfiguration/apply` will succeed or that all sections will take effect. Live apply testing uncovered these appliance-level behaviors that `/validate` does not catch:

| # | Category | Passed by `/validate` | What Happens During `/apply` on the Appliance | How the Skill Prevents It |
|---|---|---|---|---|
| 1 | **Single- vs. Multi-Segment Override** | Both `bgpSystemConfig` and `segmentBgpSystems` (or `localRoutes` + `segmentLocalRoutes`, `ospfSystemConfig` + `segmentOspfConfig`) in one YAML | Orchestrator **silently ignores** the single-segment section and applies only `segment*` | `mappers.py` omits the single-segment section whenever any non-Default segment is active and places `Default` inside `segment*` |
| 2 | **VRRP `null` Optional Strings** | `description: null` or `authenticationString: null` on `vrrp.vrrpEntries[]` | Fails with HTTP 400: `Binding is not of correct type... key: desc` | `m_vrrp` omits `description` and `authenticationString` when empty/null |
| 3 | **Branch NAT WAN Interface** | `interfaceName: wan1` on an outbound `branchNatMapsConfig` rule | Fails with `LAN interface 'wan1' not found in deployment configuration` | `validate.apply_time_error` rejects a rule on a WAN interface before `/validate` |
| 4 | **Remote DHCP Pool Without Local DHCP Server** | `dhcpRemoteAddressPoolConfig` when `deploymentInfo.dhcpInfo` has no `dhcpType: server`, and also when the same preconfig carries `deploymentInfo` (the deployment step restarts the DHCP server just before the pool step) | Fails with HTTP 400: `Cannot save remote address pool: DHCP server is not running` | `lessons.md` & `known-constraints.yaml` require a local DHCP `server` in `deploymentInfo.dhcpInfo` |
| 5 | **Remote DHCP Pool Overlap on Re-Apply** | Re-applying an existing `dhcpRemoteAddressPoolConfig` subnet or `scopeName` | Fails with HTTP 400 (`Subnet ... overlaps` or `Scope name ... already exists`) because Orchestrator sends `isEdit: false` | Documented as `merge` behavior; only net-new remote pools can be added via preconfig |
| 6 | **BGP Neighbor `enableEVPN: true` Without VXLAN** | `enableEVPN: true` on a BGP neighbor when `vxlan` is not configured | Appliance resets `evpn` to `false` during apply | Set `enableEVPN: false` unless `vxlan` is configured on the appliance |
| 7 | **Dual-Stack IPv4+IPv6 on VLAN Subinterface (`vlan > 0`)** | Two `deploymentInterfaces` entries on `lan0.71` (one IPv4, one IPv6) | Ignored/rejected on ECOS `9.6.x` (`With vlan greater than zero, we cannot have dual stack configuration`) | Keep VLAN subinterfaces single-stack on `9.6.x` |
| 8 | **LACP (`blan*`) vs. Bridge (`slan*`) Port Conflict** | `lan1` in `bridgeGroups` when `lan1` is already in `linkAggregation` on the appliance | Fails with `The following interfaces are used by link aggregation: lan1` | Ensure member ports are exclusive between `linkAggregation` and `bridgeGroups` |
| 9 | **Unassigned Virtual/Combo NIC MACs** | Referencing `lan2` when `lan2` has `mac: Unassigned` on an `EC-V` VM | Fails during deployment/LACP apply | Only reference interfaces with assigned MAC addresses on the target model |
| 10 | **Appliance ECOS Version Gating** | `dhcpRemoteAddressPoolConfig` and `multicast` validated on a `9.7.1` Orchestrator | Orchestrator skips applying them if the target appliance runs ECOS `9.6.x` (`Appliance version not supported`) | Check target appliance `softwareVersion` (`>= 9.7.0` required for `dhcpRemoteAddressPoolConfig` and `multicast`) |
| 11 | **Branch NAT Without `deploymentInfo`** | `branchNatMapsConfig` (with or without `natPools`) in a preconfig that has no `deploymentInfo` | Fails: `DeploymentInfo cannot be null when branchNatMapsConfig is configured` (ECOS 9.7.1) | `validate.validate_text` rejects the row before `/validate`, so `check.py`, `render.py` and `upload.py` never upload it |
| 12 | **Removing NAT Pools Still Used by the Current Map** | A preconfig whose `natPools` drops pools that the appliance's current branch NAT rules reference | The `natPools` step runs before `branchNatMapsConfig` and fails: `Cannot delete NAT pool: <name>, used in map: map1, priority: <n>`; the map step still succeeds | Apply twice (the second run deletes the now-unreferenced pools), or first apply a preconfig with only `deploymentInfo` + `branchNatMapsConfig` |
| 13 | **`localRoutes` Without Its Sharing Settings** | A `localRoutes` / `segmentLocalRoutes` entry with only `routes` | Resets the segment's subnet sharing: advertise local LAN off, local metric `0`, local-ASN filter off | `mappers.subnet_sharing` writes `advertiseLocalLanSubnets`, `advertiseLocalWanSubnets`, `localMetric`, `localCommunities`, `filterRoutesWithLocalASN` and `redistToSDwanFabricRouteMap` from `/systemInfo/system` `auto_subnet.vrf[<id>]` |
| 14 | **Legacy Redistribution Fields (write-only)** | `bgpSystemConfig.redistToSilverPeak/redistOspfToBgp/filterTag`, `ospfSystemConfig` `redistBgpToOspf`/`redistLocalToOspf`/`redistSubnetShareToOspf` and their metric/type/tag, `localRoutes.useSharedSubnetInfo/redistOspfToSubnetShare/ospfRedistMetric/ospfRedistTag` | The apply completes, but no appliance read returns them on ECOS 9.6.2 or 9.7.1 (redistribution is route-map based: `redistMapToOSPF`, `rtmap_to_subshare`) | Not written by `translate.py`; the ledger lists them as `unresolved` (no read source) |
| 15 | **Redaction Placeholder Left in a Row** | A `<SECRET:...>` placeholder copied from `reference.yaml` into a CSV cell | Accepted as a plain string; apply then fails (`Request body contains illegal characters` for an IPsec PSK) or stores the placeholder as the secret | `validate.validate_text` rejects any document containing `<SECRET:` |
| 16 | **Interface-Only Local Route** | A route with `interfaceName` and no `nextHop` (the appliance can hold one, for example on a deleted subinterface) | Fails: `localRoute - Next Hop cannot be empty when interface is specified` | `mappers.route_list` does not write it and ledgers it as `unresolved` |
| 17 | **Existing Route Zone** | Re-applying a route (same prefix and next hop) with a different `zone` | The apply completes but the route keeps its old zone (seen on ECOS 9.7.1: `none` stayed `none`) | Set route zones on new routes only; fix an existing route's zone on the appliance |
| 18 | **`networkRole` on a Managed Appliance** | `applianceInfo.networkRole: hub` applied to a managed `non-hub` appliance | The apply completes; the role stays `non-hub` (one observation, ECOS 9.7.1) | Set the role at onboarding (preconfig on a discovered appliance) or in Orchestrator |
| 19 | **Management Route Re-Apply** | Applying `managementRoutes` with a route the appliance already has | The apply adds another identical copy (seen on ECOS 9.6.2.1: one route listed three times after re-applies); a blank preconfig does not remove management routes | Apply management routes once, to a fresh appliance; remove extra copies on the appliance |
| 20 | **Branch NAT on a VLAN Subinterface** | `interfaceName: lan1.55` on a `branchNatMapsConfig` rule | Fails the whole section: `LAN interface ... not found in deployment configuration` | `validate.apply_time_error` rejects the row before `/validate` |
| 21 | **`no_encap` Tunnel Without `remoteIp`** | A passthrough tunnel with `tunnelEncap: no_encap` and no `remoteIp` | Fails the whole tunnel batch with HTTP 500 (ECOS 9.6.2.1) | `validate.apply_time_error` rejects the row |
| 22 | **Short IPsec Pre-Shared Key** | `presharedKey` under 8 characters | Fails: `Preshared Key must contain at least 8 characters` | `validate.apply_time_error` rejects the row |

---

## 3. Post-Approval Behavior (`replace` vs. `merge`) by Section

When a preconfiguration is applied to an already-approved appliance, Orchestrator applies each section using either **`replace`** (wipes existing appliance entries not in the YAML) or **`merge`** (adds/updates entries while keeping prior appliance entries):

- **`replace` sections:** `deploymentInfo`, `templateGroups`, `peerPriority`, `vrrp`, `ipSlaRule`, `inboundPortForwarding`, `ospfSystemConfig`, `segmentOspfConfig`, `flowRedirection`, `tunnelConfiguration`, `virtualTunnelInterface`, `pppoe`, `usblte`, `interfaceConfig`, `customApplianceTags`, `linkAggregation`, `bridgeGroups`, `segmentBfdConfigs`, `thirdPartyServicesAssociation`, `availabilityTimeSettings`, `natPools`, `branchNatMapsConfig`, `idsIpsConfig`, `nac`, `poE`, `secureWebServicesConfig`, `ipAllowList`, `multicast`.
- **`merge` sections (retain prior appliance entries on re-apply):** `localRoutes`, `segmentLocalRoutes`, `managementRoutes`, `bgpSystemConfig`, `segmentBgpSystems`, `loopbackInterface`, `dhcpRemoteAddressPoolConfig`, `vxlan`, `businessIntentOverlays` (the step is "Adding appliance to selected overlays": applying two overlays to an appliance in four left all four, ECOS 9.6.2.1 and 9.7.1), `appExpressGroups` (live on ECOS 9.7.1: applying `appExpressGroups: []` left the existing association in place; remove it with `POST /applicationDefinition/appExpressGroup/association`).
- **An empty `replace` section clears nothing:** a section sent with no entries is skipped at apply, so the appliance keeps what it had. This holds for bonds too: `linkAggregation: {linkAggregationGroups: []}`, with or without `isForceDelete: true`, left an existing bond in place (live on ECOS 9.7.1, 2026-10-21); a deployment interface on the bond is removed with `deploymentInfo`, but the bond itself must be deleted on the appliance (Orchestrator UI, or the CLI `no system bonding interface <blanN>`).
- **Section order in the YAML does not set the apply order:** Orchestrator stores a preconfig byte for byte as sent and applies its sections in its own sequence (license, link aggregation, deployment, …). A `linkAggregation` section placed after `deploymentInfo` still creates the bond first, so a deployment interface on `blanN` works either way (A/B live apply on ECOS 9.7.1, 2026-10-21). To reuse an appliance, remove such config first (tunnels, peer lists, tags), or send the section with the entries it should keep (2026-10-17, ECOS 9.6.2.1).

---

## 4. Baseline Probe Results (Orchestrator `9.7.1.42046`)

| Probe | Input | Result | Validator Error / Behavior |
|---|---|---|---|
| P00 | Default template as-is | reject | `Business Intent Overlays name is invalid: [RealTime, CriticalApps, BulkApps, DefaultOverlay]. Valid names are: [...]` |
| P01 | `applianceInfo.hostname` only | accept | Minimal valid document |
| P02 | Empty document | reject | `YAML format incorrect, line:1, column:1` |
| P03 | Broken YAML syntax | reject | `YAML format incorrect, line:2, column:13` |
| P04 | Unknown top-level section | reject | `YAML invalid, Unrecognized field: "notASection"` |
| P05 | Unknown nested field | reject | `YAML invalid, Unrecognized field: "notAField"` |
| P06 | `totalOutboundBandwidth: abc` | reject | `'abc' is not a valid long value` |
| P07 | Serial `XYZ` | reject | `Serial is not valid, must be in the form 000011112222` |
| P08 | Serial `000011112222` | accept | 12 hex characters required |
| P09 | `applianceInfo` without `hostname` | accept | `hostname` is optional in `/validate` |
| P10 | Non-existent template group | reject | `Template groups input are invalid:[...]. Valid groups are: [...]` |
| P11 | Existing template group | accept | |
| P12 | Non-existent `applianceInfo.group` | reject | `Appliance group does not exist: ...` |
| P13 | Non-existent overlay | reject | `Business Intent Overlays name is invalid: [...]` |
| P14 | Deployment with existing labels | accept | |
| P15 | Non-existent LAN label | reject | `deploymentInfo - Interface Label in lan Side is invalid: ... Valid labels are: {wan=[...], lan=[...]}` |
| P16 | Non-existent segment | reject | `deploymentInfo - Segment is invalid: ...` |
| P17 | Non-existent zone | reject | `deploymentInfo - Zone is invalid: ...` |
| P18 | `9.6.4` default template on `9.7.1` | reject | `Unrecognized field: "address"` (`9.6.4` `nac.server[].address` became `host` in `9.7.1`) |
| P19 | `10.0.0` default template on `9.7.1` | reject | `Unrecognized field: "ikePqcgroup"` (`10.0.0`-only PQC field) |
