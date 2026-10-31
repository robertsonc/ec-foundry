"""Section mappers: captured appliance data -> preconfig section values.

Each mapper takes a Ctx and returns the section value, or None when the source does not use the feature (the ledger says why).
Rules shared by all mappers:
  * Source objects marked gms_marked / gmsMarked are created by Orchestrator services (overlay manager, SSE, ...). They are not
    intent, so they are skipped and ledgered as `orchestrator-managed`.
  * Source keys a mapper does not consume are reported in the ledger (`unmapped-source-key`), so nothing disappears silently.
  * IDs are resolved to names (label, zone, segment, role). Empty strings become null (key present, no value).
  * Secret values arrive redacted (`<SECRET:path>`); they stay as that placeholder in reference.yaml and become empty CSV cells.
Every mapping is checked against the validator (check.py --validate); evidence for a mapping is a validated example.
"""
import re
from contextlib import contextmanager
from typing import Any, Callable, Dict, List, Optional, Tuple

ADMIN = {True: "Up", False: "Down"}
ECOS_RELEASE = re.compile(r"^\d+\.\d+(\.\d+)*(_\d+)?$")  # 9.7, 9.6.2.1, 9.6.2.1_107093


def nul(value: Any) -> Any:
    return None if value in ("", None) else value


def managed(item: Any) -> bool:
    return isinstance(item, dict) and bool(item.get("gms_marked") or item.get("gmsMarked"))


class Ctx:
    def __init__(self, cap: Any, notes: List[Dict[str, Any]], target_ecos: Optional[str] = None) -> None:
        self.cap, self.notes = cap, notes
        self.target_ecos = target_ecos  # ECOS release of the target appliance (translate --target-ecos); None: unknown. No rule reads it at present
        self.nepk = cap.run["appliance"]["nePk"]
        dep = cap.data("deployment") or {}
        dep = dep if isinstance(dep, dict) else {}
        cfg = dep.get("sysConfig") or {}  # `or`: keys can be present but null
        cfg = cfg if isinstance(cfg, dict) else {}
        # a map whose whole read is unusable: resolving a name through it raises Unreadable, so no section is written with names missing
        self.unread_maps: set = set()
        where, target = "deployment.sysConfig.", "deploymentInfo.deploymentInterfaces"

        def names(key: str, item: str, objs: Any) -> Dict[str, Any]:
            found = id_names(self, item, objs, section=target, strict=True)  # one id without a name would be written as null
            if found is None:
                self.unread_maps.add(key)
            return found or {}

        sides = cfg.get("ifLabels") or {}
        if not isinstance(sides, dict):
            unreadable_read(self, where + "ifLabels", "interface labels are not resolved to names", target)
            self.unread_maps.add("ifLabels")
            sides = {}
        self.labels = {k: v for side, items in sides.items() for k, v in names("ifLabels", "{}ifLabels.{}".format(where, side), items).items()}
        self.vrfs = names("vrfs", where + "vrfs", cfg.get("vrfs"))
        zone_map = cfg.get("vrfZonesMap") or {}
        if not isinstance(zone_map, dict):
            unreadable_read(self, where + "vrfZonesMap", "zones are not resolved to names", target)
            self.unread_maps.add("vrfZonesMap")
            zone_map = {}
        self.zones = {vrf: names("vrfZonesMap", "{}vrfZonesMap.{}".format(where, vrf), list(m.values())) if isinstance(m, dict) else {} for vrf, m in zone_map.items()}
        self.roles = names("roles", where + "roles", cfg.get("roles"))
        self.route_labels: Optional[Dict[str, str]] = None  # read from the running-config on first use

    def mode_ifs(self) -> List[Any]:
        """deployment.modeIfs; Unreadable when the read has another shape, never taken as "no interfaces"."""
        dep = self.data("deployment") or {}
        found = dep.get("modeIfs", []) if isinstance(dep, dict) else None
        if not isinstance(found, list):
            raise Unreadable("the interfaces (deployment.modeIfs) could not be read")
        for m in found:  # the interface an entry names may be the one a section needs
            entries = m.get("applianceIPs") if isinstance(m, dict) and isinstance(m.get("ifName"), str) else None
            if not isinstance(entries, list) or not all(isinstance(a, dict) and str(a.get("vlan") or 0).isdecimal() for a in entries):
                raise Unreadable("an interface entry (deployment.modeIfs) could not be read")
        return found

    def readable(self, key: str) -> None:
        if key in self.unread_maps:
            raise Unreadable("the {} names (deployment.sysConfig.{}) could not be read".format({"ifLabels": "interface label", "vrfs": "segment", "vrfZonesMap": "zone", "roles": "role"}[key], key))

    def data(self, ident: str, prefer: str = "live") -> Any:
        return self.cap.data(ident, prefer)

    def note(self, item: str, disposition: str, target: str = "", why: str = "") -> None:
        entry = {"item": item, "disposition": disposition, "target": target, "note": why}
        if entry not in self.notes:  # route_list runs once per check and once to build, so its notes repeat
            self.notes.append(entry)

    def label(self, ident: Any) -> Optional[str]:
        self.readable("ifLabels")
        return self.labels.get(str(ident)) if str(ident) not in ("", "None") else None

    def route_label(self, ident: Any, item: str, what: str, target: str) -> Optional[str]:
        """Route-label name for a route-label id. Route labels are their own dictionary (/cn/rtlabels in the running-config), never the interface
        labels; an id they do not name is written as null and ledgered, not guessed."""
        if str(ident) in ("", "None", "0"):
            return None
        if self.route_labels is None:
            found = (re.match(r"^internal set modify - /cn/rtlabels/config/(\d+)/name value string (.+)$", l) for l in cli_lines(self))
            self.route_labels = {m.group(1): re.sub(r'^"(.*)"$', r"\1", m.group(2)) for m in found if m}
        name = self.route_labels.get(str(ident))
        if name is None and not self.route_labels and not cli_lines(self):
            self.note(item, "unresolved", target, "{} has route label id {}, but no stored running-config could be read, so route label names are unknown; routeLabel written as null, set it by hand".format(what, ident))
        elif name is None:
            self.note(item, "unresolved", target, "{} has route label id {}, which the running-config's route labels (/cn/rtlabels) do not name; routeLabel written as null, set it by hand".format(what, ident))
        else:
            cli_note(self, target, "route label names from /cn/rtlabels")
        return name

    def segment(self, vrf: Any, strict: bool = True) -> Optional[str]:
        """Segment name of a vrf id. strict (for written values): an id that names no segment raises Unresolved, since a null segment
        applies to the Default segment; strict=False gives None, for ledger text only."""
        self.readable("vrfs")
        name = self.vrfs.get(str(vrf))
        if name is None and strict:
            raise Unresolved("vrf id {} names no segment".format(vrf))
        return name

    def zone(self, vrf: Any, zone: Any) -> Optional[str]:
        self.readable("vrfZonesMap")
        return self.zones.get(str(vrf), {}).get(str(zone))

    def role(self, ident: Any) -> Optional[str]:
        self.readable("roles")
        name = self.roles.get(str(ident))
        return None if name in (None, "default") else name

    def failed(self, target: str, item: str = "") -> bool:
        """Whether an item under target (and starting with item) was ledgered as unreadable; a default-omitted note would contradict it."""
        return any(n["disposition"] in ("toolkit-error", "not-readable", "unresolved") and (n["target"] == target or n["target"].startswith(target + ".")) and n["item"].startswith(item) for n in self.notes)

    def unmapped(self, item: str, source: Dict[str, Any], used: set, target: str) -> None:
        left = sorted(k for k in source if k not in used and k not in ("gms_marked", "gmsMarked", "self"))
        if left:
            self.note(item, "unmapped-source-key", target, "source keys not mapped: " + ", ".join(left))


def vrf_dict(ctx: Ctx, ident: str, default_only: bool = True) -> Any:
    return ctx.data(ident)


ITEM_ERRORS = (KeyError, TypeError, ValueError, AttributeError, StopIteration, IndexError)


class Unreadable(ValueError):
    """A capture read the item depends on was not readable: nothing can be said about the item, so it is not written."""


class Unresolved(ValueError):
    """An id in the item names nothing the capture knows (a vrf id of a deleted segment): the item is not written, never with a null name."""


def item_failed(ctx: Ctx, item: str, section: str, err: Exception) -> None:
    """One source item the mapper could not read: ledgered and skipped, so the rest of its section is still written."""
    if isinstance(err, Unreadable):
        ctx.note(item, "not-readable", section, "{} not written: {}; check it by hand".format(item, err))
        return
    if isinstance(err, Unresolved):
        ctx.note(item, "unresolved", section, "{} not written: {}; set it by hand if it is still wanted".format(item, err))
        return
    ctx.note(item, "toolkit-error", section, "{} not written: the mapper could not read it ({}: {}); a toolkit bug to report".format(item, type(err).__name__, err))


@contextmanager
def guarded(ctx: Ctx, item: str, section: str) -> Any:
    """Run a block that reads one source item: an unexpected shape is ledgered (item_failed) and the block skipped, never the whole translation."""
    try:
        yield
    except ITEM_ERRORS as err:
        item_failed(ctx, item, section, err)


def read_failed(cap: Any, ident: str) -> bool:
    """The capture made the read but holds no usable copy, live or cached; a 404 everywhere means absent on this appliance, not failed."""
    tries = [i for i in getattr(cap, "index", None) or [] if i.get("id") == ident]
    return bool(tries) and not any(i.get("status") == "ok" for i in tries) and not all(i.get("http") == 404 for i in tries)


def failed_read(ctx: Ctx, ident: str, what: str, section: str = "") -> bool:
    """read_failed, ledgered not-readable: nothing is written from a read that failed, and it is never taken as empty."""
    if not read_failed(ctx.cap, ident):
        return False
    ctx.note(ident, "not-readable", section, "the {} read failed (no usable live or cached copy), so {}; check by hand".format(ident, what))
    return True


def unreadable_read(ctx: Ctx, item: str, what: str, section: str = "") -> None:
    ctx.note(item, "not-readable", section, "the read has an unexpected shape, so {}; check them by hand".format(what))


def id_names(ctx: Ctx, item: str, objs: Any, key: Callable[[Any], Any] = str, section: str = "", strict: bool = False) -> Optional[Dict[Any, Any]]:
    """{key(id): name} of a list of {id, name} objects (as dict comprehension: a later id wins). A read of another type is ledgered
    not-readable and gives None; an object of another shape is ledgered toolkit-error and skipped, and with strict the map is then None too."""
    if not objs:
        return {}
    if not isinstance(objs, list):
        unreadable_read(ctx, item, "its ids are not resolved to names", section)
        return None
    out: Dict[Any, Any] = {}
    complete = True
    for i, obj in enumerate(objs):
        try:
            out[key(obj["id"])] = obj["name"]
        except ITEM_ERRORS as err:
            item_failed(ctx, "{}[{}]".format(item, i), section, err)
            complete = False
    return out if complete or not strict else None


def num_key(key: Any) -> Tuple[int, int, str]:
    """Sort key for numeric ids that never raises: numbers first in numeric order, anything else after them."""
    return (0, int(key), "") if str(key).isdecimal() else (1, 0, str(key))


def block(data: Dict[str, Any], key: str) -> Dict[str, Any]:
    """data[key] as a dict: {} when the key is absent, an error when it is present but unreadable (null or another type), so the caller's
    per-item guard ledgers it instead of writing an empty list."""
    if data is None:
        raise Unreadable("the read holding {} could not be read".format(key))
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise TypeError("{} is {}, not an object".format(key, type(value).__name__))
    return value


def each(ctx: Ctx, item: str, section: str, pairs: Any, build: Any) -> List[Any]:
    """build(key, value) for every pair, skipping (and ledgering) the ones that fail."""
    out = []
    for key, value in pairs:
        try:
            out.append(build(key, value))
        except ITEM_ERRORS as err:
            item_failed(ctx, "{}[{}]".format(item, key), section, err)
    return out


OSPF_IF_USED = {"area", "cost", "priority", "adminStatus", "helloInterval", "deadInterval", "transmitDelay", "retransmitInterval", "authType", "authKey", "md5Key", "md5Password", "comment", "bfdDesired"}


def ospf_area(area: str, a: Dict[str, Any]) -> Dict[str, Any]:
    return {"areaId": area, "areaType": a["area_type"], "redist": a["redist"], "summary": a["summary"], "translatorRole": a["translator_role"]}


def ospf_interface(name: str, i: Dict[str, Any]) -> Dict[str, Any]:
    return {"interfaceName": name, "areaId": i["area"], "cost": i["cost"], "priority": i["priority"], "adminStatus": ADMIN[bool(i["adminStatus"])], "helloInterval": i["helloInterval"],
            "deadInterval": i["deadInterval"], "transmitDelay": i["transmitDelay"], "retransmitInterval": i["retransmitInterval"], "authentication": i["authType"],
            "authenticationKey": nul(i["authKey"]), "md5Key": i["md5Key"], "md5Password": nul(i["md5Password"]), "comment": nul(i["comment"])}


def carried_ifs(ctx: Ctx) -> Tuple[set, set]:
    """(interfaces the preconfig creates, Orchestrator-managed ones): deployment entries (ifName or ifName.vlan) and user loopbacks and VTIs;
    gms_marked loopbacks and VTIs. Unreadable when the interfaces read is."""
    names, gms = {"{}.{}".format(m["ifName"], int(a.get("vlan") or 0)) if int(a.get("vlan") or 0) > 0 else m["ifName"] for m in ctx.mode_ifs() for a in m["applianceIPs"]}, set()
    for ident in ("loopbacks", "vtis"):
        src = ctx.data(ident)
        for k, v in (src.items() if isinstance(src, dict) else []):
            (gms if managed(v) else names).add(k)
    return names, gms


def note_ref(ctx: Ctx, item: str, target: str, what: str, iface: Any) -> None:
    """Ledger a written field that names an interface the preconfig does not create. The value is kept: it is the source's own setting and the
    target may already have the interface (an interface label name counts as carried)."""
    if iface in (None, "", "any", "default"):
        return
    try:
        names, gms = carried_ifs(ctx)
    except Unreadable:  # ledgered where the interfaces are read
        return
    if iface in names or iface in ctx.labels.values():
        return
    if iface in gms:
        ctx.note(item, "orchestrator-managed", target, "{} references interface {}, an Orchestrator-managed interface (gms_marked); the target's Orchestrator must create it".format(what, iface))
    else:
        ctx.note(item, "unresolved", target, "{} references interface {}, which this preconfig does not create; the target must already have it".format(what, iface))


def deployed(ctx: Ctx, item: str, target: str, ifs: Dict[str, Any]) -> Dict[str, Any]:
    """The routing interfaces of ifs that the preconfig creates (carried_ifs). The others are ledgered and left out: Orchestrator-managed
    loopbacks/VTIs (gms_marked), and interfaces nothing in the preconfig deploys, which apply cannot configure."""
    names, gms = carried_ifs(ctx)
    for name in sorted(set(ifs) - names):
        if name in gms:
            ctx.note(item, "orchestrator-managed", target, "OSPF interface {} is an Orchestrator-managed interface (gms_marked); not written".format(name))
        else:
            ctx.note(item, "unresolved", target, "OSPF interface {} is not deployed in this preconfig (no deployment interface, loopback or VTI); not written".format(name))
    return {k: v for k, v in ifs.items() if k in names}


def m_ospfSystemConfig(ctx: Ctx) -> Optional[Dict[str, Any]]:
    all_systems, all_ifs = ctx.data("ospf-system-all-vrfs") or {}, ctx.data("ospf-interfaces-all-vrfs")
    if any(vrf != "0" and ospf_runs(all_systems, all_ifs, vrf) for vrf in all_systems):
        ctx.note("ospf-system", "default-omitted", "ospfSystemConfig", "non-default segment OSPF exists, so Default segment OSPF is included in segmentOspfConfig (Orchestrator ignores ospfSystemConfig when segmentOspfConfig is present)")
        return None
    system, areas, ifs = ctx.data("ospf-system"), ctx.data("ospf-areas"), ctx.data("ospf-interfaces")
    if not system or (not system.get("enable") and not ifs):
        ctx.note("ospf-system", "default-omitted", "ospfSystemConfig", "OSPF disabled and no interfaces")
        return None
    if ifs is None:  # interfaces replace on apply: an unread list is never written as an empty one
        ctx.note("ospf-interfaces", "not-readable", "ospfSystemConfig.interfaces", "OSPF is enabled but its interfaces could not be read, so ospfSystemConfig is not written; check it by hand")
        return None
    out: Dict[str, Any] = {"enable": system["enable"], "routerId": nul(system.get("routerId")), "redistMapToOspf": nul(system.get("redistMapToOSPF")), "opaqueEnable": system.get("opaque_enable")}
    ctx.unmapped("ospf-system", system, {"enable", "routerId", "redistMapToOSPF", "opaque_enable"}, "ospfSystemConfig")
    src_areas = sorted(((areas or {}).get("0") or {}).items())
    out["areas"] = each(ctx, "ospf-areas", "ospfSystemConfig.areas", src_areas, ospf_area)

    def interface(name: str, i: Dict[str, Any]) -> Dict[str, Any]:
        entry = dict(ospf_interface(name, i), bfdEnabled=i["bfdDesired"])
        ctx.unmapped("ospf-interfaces[{}]".format(name), i, OSPF_IF_USED, "ospfSystemConfig.interfaces")
        return entry
    ifs = deployed(ctx, "ospf-interfaces", "ospfSystemConfig.interfaces", ifs)
    out["interfaces"] = each(ctx, "ospf-interfaces", "ospfSystemConfig.interfaces", sorted(ifs.items()), interface)
    if (ifs and not out["interfaces"]) or (src_areas and not out["areas"]):  # every item failed: an empty list would replace the target's on apply
        return None
    ctx.note("ospf-system, ospf-areas, ospf-interfaces", "mapped", "ospfSystemConfig", "default VRF only; interface adminStatus true/false written as Up/Down")
    return out


def m_loopbackInterface(ctx: Ctx) -> Optional[Dict[str, Any]]:
    source = ctx.data("loopbacks") or {}
    items = [(k, v) for k, v in sorted(source.items()) if not managed(v)]
    skipped = len(source) - len(items)
    if skipped:
        ctx.note("loopbacks", "orchestrator-managed", "loopbackInterface", "{} loopbacks created by Orchestrator services (gms_marked)".format(skipped))
    if not items:
        return None
    out = each(ctx, "loopbacks", "loopbackInterface", items, lambda k, v: {"interfaceId": k, "adminStatus": ADMIN[bool(v["admin"])], "ipAddressMask": "{}/{}".format(v["ipaddr"], v["nmask"]),
               "interfaceLabel": ctx.label(v["label"]), "zone": ctx.zone(v["vrf_id"], v["zone"]), "role": ctx.role(v.get("role_id", 0)), "segment": ctx.segment(v["vrf_id"])})
    if not out:
        return None
    ctx.note("loopbacks", "mapped", "loopbackInterface", "{} loopbacks".format(len(out)))
    return {"loopbacks": out}


def m_linkAggregation(ctx: Ctx) -> Optional[Dict[str, Any]]:
    source = ctx.data("link-aggregation") or {}
    if not source:
        return None

    def group(k: str, v: Dict[str, Any]) -> Dict[str, Any]:
        entry = {"channelGroup": k, "interfaces": v["portlist"], "mtu": v["mtu"], "mode": v["mode"], "lacpRate": v["lacp_rate"], "lacpSystemPriority": v["lacp_sys_prio"], "lacpComment": nul(v["comment"])}
        ctx.unmapped("link-aggregation[{}]".format(k), v, {"portlist", "mtu", "mode", "lacp_rate", "lacp_sys_prio", "comment"}, "linkAggregation")
        return entry
    groups = each(ctx, "link-aggregation", "linkAggregation", sorted(source.items()), group)
    if not groups:
        return None
    ctx.note("link-aggregation", "mapped", "linkAggregation", "{} bonded interfaces; isForceDelete has no source and is omitted".format(len(groups)))
    return {"linkAggregationGroups": groups}


def m_segmentBfdConfigs(ctx: Ctx) -> Optional[List[Dict[str, Any]]]:
    source = ctx.data("bfd-vrfs") or {}
    out = [b for b in each(ctx, "bfd-vrfs", "segmentBfdConfigs", sorted(source.items()), lambda k, v: {
        "segment": ctx.segment(k), "enable": v["enable"], "minRxInterval": v["minRxInterval"], "minTxInterval": v["minTxInterval"], "detectMultiplier": v["detectMultiplier"]} if v.get("enable") else None) if b]
    if not out:
        if not ctx.failed("segmentBfdConfigs"):
            ctx.note("bfd-vrfs", "default-omitted", "segmentBfdConfigs", "BFD disabled in every segment")
        return None
    ctx.note("bfd-vrfs", "mapped", "segmentBfdConfigs", "{} segments with BFD enabled".format(len(out)))
    return out


def m_customApplianceTags(ctx: Ctx) -> Optional[Dict[str, Any]]:
    source = ctx.data("custom-tags") or {}
    ordered = sorted(source.items(), key=lambda kv: num_key(kv[0]))
    tags = [t for t in each(ctx, "custom-tags", "customApplianceTags", ordered, lambda k, v: {"tagId": int(k), "key": v["name"], "value": v["value"]} if v.get("name") else None) if t]
    if not tags:
        if not ctx.failed("customApplianceTags"):
            ctx.note("custom-tags", "default-omitted", "customApplianceTags", "no tag has a name")
        return None
    ctx.note("custom-tags", "mapped", "customApplianceTags", "{} named tags".format(len(tags)))
    return {"customApplianceTagsInterfaces": tags}


def m_inboundPortForwarding(ctx: Ctx) -> Optional[Dict[str, Any]]:
    raw = ctx.data("port-forwarding") or []
    ha_rules = [r for r in raw if isinstance(r, dict) and r.get("comment") == "HA rule"]
    if ha_rules:
        ctx.note("port-forwarding", "orchestrator-managed", "inboundPortForwarding", "{} rules with comment 'HA rule' generated by EdgeHA".format(len(ha_rules)))
    source = [(i, r) for i, r in enumerate(raw) if not managed(r) and r not in ha_rules]  # i: position in the captured list, which the ledger names
    if not source:
        return None
    wan_label_by_if = {}
    for m in ctx.mode_ifs():
        for a in m.get("applianceIPs", []):
            if a.get("wanSide") and a.get("label"):
                vlan = int(a.get("vlan") or 0)
                ifname = "{}.{}".format(m["ifName"], vlan) if vlan > 0 else m["ifName"]
                wan_label_by_if[ifname] = ctx.label(a["label"])
    rules = []
    seen = set()
    for i, r in source:
        try:
            src_if = r["srcIf"] or "any"
            if str(src_if).isdigit():
                src_if = ctx.label(src_if) or "any"
            elif src_if.startswith("lan"):
                src_if = wan_label_by_if.get(src_if) or "any"
            entry = {"sourceIpSubnet": r["srcSubnet"], "destinationIpSubnet": r["destSubnet"], "translate": bool(r.get("targetIp")), "destinationPortRange": nul(r["destPort"]),
                     "destinationProtocol": nul(r["protocol"]), "translateIp": nul(r["targetIp"]), "translatePortRange": nul(r["targetPort"]),
                     "sourceInterface": src_if, "segment": ctx.segment(r["vrf_id"]), "comment": nul(r["comment"])}
        except ITEM_ERRORS as err:
            item_failed(ctx, "port-forwarding[{}]".format(i), "inboundPortForwarding", err)
            continue
        sig = tuple(sorted(entry.items()))
        if sig not in seen:
            seen.add(sig)
            rules.append(entry)
        ctx.unmapped("port-forwarding", r, {"srcSubnet", "destSubnet", "destPort", "protocol", "targetIp", "targetPort", "srcIf", "vrf_id", "comment"}, "inboundPortForwarding")
    if not rules:
        return None
    ctx.note("port-forwarding", "mapped", "inboundPortForwarding", "{} rules".format(len(rules)))
    return {"portForwardingRules": rules}


def flow_process(url: Dict[str, Any], source: Dict[str, Any]) -> Tuple[bool, Optional[Tuple[str, str]]]:
    """urlClassificationConfig.flowProcess as a boolean, with the (disposition, note) to ledger when the section is written.

    The 10.0.0 default template marks it required (true: WebCC treatment of all requests, the default; false: first request only).
    Orchestrator 10.0.0 /validate answers "Secure Web Services Config - Not valid value: flowProcess." when it is null or missing;
    true, false and the text "true"/"false" are accepted (lab, 10.0.0.40724, 2026-10-31). GET /secureWebServicesConfig of an
    appliance on ECOS 9.7.2 behind that Orchestrator holds flowProcess: null, so the default is written. A 9.x target drops the key
    again (not in its default template)."""
    raw = url.get("flowProcess", source.get("flowProcess"))
    if isinstance(raw, bool):
        return raw, None
    if isinstance(raw, str) and raw.strip().lower() in ("true", "false"):
        return raw.strip().lower() == "true", None
    if raw is None:
        return True, ("mapped", "the appliance reports no flowProcess value (null or absent: ECOS before 10.0): written true, the default template value (WebCC treatment of all requests)")
    return True, ("not-readable", "flowProcess read as {!r}, not a boolean: written true, the default template value; check the WebCC treatment (all requests / first request) by hand".format(raw))


def m_secureWebServicesConfig(ctx: Ctx) -> Optional[Dict[str, Any]]:
    source = (ctx.data("secure-web-services") or {}).get("secureWebServicesConfig") or {}
    if not isinstance(source, dict):
        raise Unreadable("secureWebServicesConfig could not be read ({})".format(type(source).__name__))
    url, ip = source.get("urlClassificationConfig"), source.get("ipReputationConfig")
    if (url is not None and not isinstance(url, dict)) or (ip is not None and not isinstance(ip, dict)):
        raise Unreadable("secureWebServicesConfig.urlClassificationConfig or .ipReputationConfig could not be read")
    url_defaults = {"hasURLClassification": False, "incrementalUpdate": False, "queryOnMiss": False, "urlReputation": 1}  # default template values
    ip_defaults = {"hasIPReputation": False, "incrementalUpdate": False}
    url_value = {k: v for k, v in (url or {}).items() if k != "flowProcess"}
    flow, flow_note = flow_process(url or {}, source) if url is not None else (True, None)
    if not source.get("hasSecureWebServicesConfig") and url_value in ({}, url_defaults) and (ip or {}) in ({}, ip_defaults) and flow is True:
        ctx.note("secure-web-services", "default-omitted", "secureWebServicesConfig", "feature not configured")
        return None
    url_value["flowProcess"] = flow
    if flow_note:
        ctx.note("secure-web-services", flow_note[0], "secureWebServicesConfig.urlClassificationConfig.flowProcess", flow_note[1])
    ctx.note("secure-web-services", "mapped", "secureWebServicesConfig", "url classification and IP reputation")
    return {"urlClassificationConfig": url_value, "ipReputationConfig": dict(ip or ip_defaults)}


BGP_NEIGHBOR_USED = {"remote_as", "type", "enable", "hold", "ka", "lcl_interface", "next_hop_self", "password", "rtmap_inbound", "rtmap_outbound", "evpn", "bfd_desired", "directly_connected", "store_received_routes"}


def bgp_value(ctx: Ctx, label: str, system: Dict[str, Any], neighbors: Dict[str, Any], vrf: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """BGP of the Default segment, or with vrf of that segment (segmentBgpSystems)."""
    live = [(ip, n) for ip, n in sorted((neighbors or {}).items()) if not managed(n)]
    skipped = sorted(ip for ip, n in (neighbors or {}).items() if managed(n))
    if skipped and label != "check":
        ctx.note(label, "orchestrator-managed", "segmentBgpSystems.neighbors" if vrf is not None else "bgpSystemConfig.neighbors",
                 "{} BGP neighbor(s) created by Orchestrator services (gms_marked) not written: {}".format(len(skipped), ", ".join(skipped)))
    if system is None and vrf is not None:
        raise Unreadable("the segment's BGP settings could not be read")
    if not system and live:  # a non-dict system that is truthy fails on .get below
        raise Unreadable("BGP settings could not be read ({}) while {} neighbor(s) exist".format(type(system).__name__, len(live)))
    if not system or (not system.get("enable") and not live):
        return None
    if neighbors is None:  # neighbors replace on apply: an unread list is never written as an empty one
        raise Unreadable("BGP is enabled but its neighbors could not be read")
    rt = (system.get("route_target") or {}).get("0") or {}
    out: Dict[str, Any] = {}
    if vrf is not None:
        out["segment"] = ctx.segment(vrf)
    out.update({"enable": system["enable"], "asn": system["asn"], "routerId": nul(system.get("rtr_id")), "enableGracefulRestart": system.get("graceful_restart_en"),
                "maxRestartTime": system.get("max_restart_time"), "maxStalePathTime": system.get("stale_path_time"), "propagateAsPath": system.get("remote_as_path_advertise")})
    if rt and (rt.get("import"), rt.get("export")) != ("0:0", "0:0"):
        out["importRouteTarget"], out["exportRouteTarget"] = rt.get("import"), rt.get("export")
    elif rt:
        ctx.note(label, "default-omitted", "bgpSystemConfig.import/exportRouteTarget", "0:0 means no route target (the validator rejects ASN 0)")
    ctx.unmapped(label, system, {"enable", "asn", "rtr_id", "graceful_restart_en", "max_restart_time", "stale_path_time", "remote_as_path_advertise", "route_target", "neighbor", "enable_gms_marked", "log_nbr_msgs"}, "bgpSystemConfig")
    out["neighbors"] = []
    target = "segmentBgpSystems.neighbors" if vrf is not None else "bgpSystemConfig.neighbors"
    failed = 0
    for ip, n in live:
        try:
            nb = {"peerIpAddress": ip, "sourceIpInterface": nul(n.get("lcl_interface")), "peerAsn": n["remote_as"], "peerType": n["type"], "enableNeighbor": n["enable"],
                                 "softReconfiguration": n["store_received_routes"], "nextHopSelf": n["next_hop_self"], "inboundRouteMap": nul(n.get("rtmap_inbound")),
                                 "outboundRouteMap": nul(n.get("rtmap_outbound")), "keepAlive": n["ka"], "holdTime": n["hold"], "password": nul(n.get("password")),
                                 "enableEVPN": n.get("evpn", False), "bfdEnabled": n.get("bfd_desired", False), "peerAdjacency": "SINGLE_HOP" if n["directly_connected"] else "MULTI_HOP"}
        except ITEM_ERRORS as err:
            failed += 1
            if label != "check":  # m_bgpSystemConfig/m_segmentBgpSystems probe each segment once with label "check" first
                item_failed(ctx, "{} neighbor {}".format(label, ip), target, err)
            continue
        out["neighbors"].append(nb)
        if label != "check":
            note_ref(ctx, "{} neighbor {}".format(label, ip), target + ".sourceIpInterface", "BGP neighbor " + ip, nb["sourceIpInterface"])
        ctx.unmapped("{} neighbor {}".format(label, ip), n, BGP_NEIGHBOR_USED, target)
    if failed and not out["neighbors"]:  # neighbors replace on apply: an empty list would remove the target's
        raise ValueError("no BGP neighbor could be read")
    return out


def has_bgp(ctx: Ctx, system: Dict[str, Any], neighbors: Dict[str, Any], vrf: str) -> bool:
    """Whether segment vrf runs BGP; an unreadable segment counts as yes, so the per-segment pass writes the rest and ledgers it."""
    if system is None:
        return True
    try:
        return bool(bgp_value(ctx, "check", system, block(neighbors, vrf)))
    except ITEM_ERRORS:
        return True


def m_bgpSystemConfig(ctx: Ctx) -> Optional[Dict[str, Any]]:
    systems, neighbors = ctx.data("bgp-system-all-vrfs") or {}, ctx.data("bgp-neighbors-all-vrfs")
    if any(vrf != "0" and has_bgp(ctx, systems[vrf], neighbors, vrf) for vrf in systems):
        ctx.note("bgp-system, bgp-neighbors", "default-omitted", "bgpSystemConfig", "non-default segment BGP exists, so Default segment BGP is included in segmentBgpSystems (Orchestrator ignores bgpSystemConfig when segmentBgpSystems is present)")
        return None
    try:
        out = bgp_value(ctx, "bgp-system", ctx.data("bgp-system"), ctx.data("bgp-neighbors"))
    except ITEM_ERRORS as err:
        item_failed(ctx, "bgp-system", "bgpSystemConfig", err)
        return None
    ctx.note("bgp-system, bgp-neighbors", "mapped" if out else "default-omitted", "bgpSystemConfig", "default segment" if out else "BGP disabled and no neighbors")
    return out


def m_segmentBgpSystems(ctx: Ctx) -> Optional[List[Dict[str, Any]]]:
    systems, neighbors = ctx.data("bgp-system-all-vrfs") or {}, ctx.data("bgp-neighbors-all-vrfs")
    non_default = [vrf for vrf in sorted(systems) if vrf != "0" and has_bgp(ctx, systems[vrf], neighbors, vrf)]
    if not non_default:
        ctx.note("bgp-system-all-vrfs", "default-omitted", "segmentBgpSystems", "0 non-default segments with BGP")
        return None
    out = [v for v in each(ctx, "bgp-system-all-vrfs", "segmentBgpSystems", sorted(systems.items()),
                           lambda vrf, s: bgp_value(ctx, "bgp-system-all-vrfs[{}]".format(vrf), s, block(neighbors, vrf), vrf)) if v]
    for vrf in sorted(systems):
        if not any(v.get("segment") == ctx.segment(vrf, strict=False) for v in out) and not ctx.failed("segmentBgpSystems", "bgp-system-all-vrfs[{}]".format(vrf)):
            ctx.note("bgp-system-all-vrfs[{}]".format(vrf), "default-omitted", "segmentBgpSystems", "segment {}: BGP disabled with no neighbors (ASN and router ID stay on the source only)".format(ctx.segment(vrf, strict=False)))
    if out:
        ctx.note("bgp-system-all-vrfs", "mapped", "segmentBgpSystems", "{} segments with BGP (includes Default when non-default segments use BGP)".format(len(out)))
    return out or None


def m_vrrp(ctx: Ctx) -> Optional[Dict[str, Any]]:
    source = ctx.data("vrrp") or []
    if not source:
        return None
    runtime = {"master_transitions", "masterip", "mode", "uptime", "vipowner", "vmac", "priorityState"}
    out = []
    for v in source:
        try:
            entry: Dict[str, Any] = {
                "groupId": v["groupId"], "interfaceName": v["interface"], "admin": v["enable"],
                "virtualIpAddress": v["vipaddr"], "advertisementTimer": v["adv_timer"], "priority": v["priority"],
                "tracker": v.get("tracker", False), "version": v["version"], "preemption": v["preempt"],
            }
            if v.get("auth"):
                entry["authenticationString"] = v["auth"]
            if v.get("desc"):
                entry["description"] = v["desc"]
            entry.update({"packetTrace": v["pkt_trace"], "holddownTimer": v["holddown"]})
        except ITEM_ERRORS as err:
            item_failed(ctx, "vrrp group {}".format(v.get("groupId") if isinstance(v, dict) else v), "vrrp", err)
            continue
        out.append(entry)
        note_ref(ctx, "vrrp group {}".format(v["groupId"]), "vrrp.interfaceName", "VRRP group {}".format(v["groupId"]), entry["interfaceName"])
        ctx.unmapped("vrrp group {}".format(v["groupId"]), v, {"groupId", "interface", "enable", "vipaddr", "adv_timer", "priority", "tracker", "version", "preempt", "auth", "desc", "pkt_trace", "holddown"} | runtime, "vrrp")
    if not out:
        return None
    ctx.note("vrrp", "mapped", "vrrp", "{} groups; empty auth/desc omitted because null desc fails at apply time on ECOS".format(len(out)))
    return {"vrrpEntries": out}


def m_natPools(ctx: Ctx) -> Optional[List[Dict[str, Any]]]:
    source = ctx.data("nat-pools") or {}
    if not source:
        return None
    try:
        out = [{"name": v["name"], "segment": ctx.segment(v["segment"]), "direction": v["dir"], "poolIpSubnet": v["subnet"], "translatePorts": bool(v["pat"]), "comment": nul(v["comment"])}
               for k, v in sorted(source.items(), key=lambda kv: int(kv[0]))]
    except Unresolved as err:  # all or nothing: branch NAT rules refer to pools by list position
        item_failed(ctx, "nat-pools", "natPools", err)
        return None
    for k, v in source.items():
        ctx.unmapped("nat-pools[{}]".format(k), v, {"name", "segment", "dir", "subnet", "pat", "comment"}, "natPools")
    ctx.note("nat-pools", "mapped", "natPools", "{} pools; the numeric pool id (source key) is not part of the preconfig".format(len(out)))
    return out


def m_bridgeGroups(ctx: Ctx) -> Optional[List[Dict[str, Any]]]:
    source = ctx.data("bridge-groups") or {}
    if not source:
        return None

    def group(k: str, v: Dict[str, Any]) -> Dict[str, Any]:
        entry = {"bridgeGroup": k, "interfaces": v["portlist"], "mtu": v["mtu"], "adminStatus": ADMIN[bool(v["admin"])], "comment": nul(v["comments"])}
        ctx.unmapped("bridge-groups[{}]".format(k), v, {"portlist", "mtu", "admin", "comments"}, "bridgeGroups")
        return entry
    out = each(ctx, "bridge-groups", "bridgeGroups", sorted(source.items()), group)
    if not out:
        return None
    ctx.note("bridge-groups", "mapped", "bridgeGroups", "{} groups".format(len(out)))
    return out


def ospf_kept(system: Dict[str, Any], interfaces: Any) -> bool:
    """A segment's OSPF is written when it runs, or when it is switched off but still configured on interfaces (kept with enable false)."""
    return bool(system.get("enable") or interfaces)


def ospf_runs(systems: Dict[str, Any], interfaces: Dict[str, Any], vrf: str) -> bool:
    """ospf_kept for one segment; an unreadable segment counts as yes, so the per-segment pass writes the rest and ledgers it."""
    try:
        return ospf_kept(systems[vrf], block(interfaces, vrf))
    except ITEM_ERRORS:
        return True


def m_segmentOspfConfig(ctx: Ctx) -> Optional[List[Dict[str, Any]]]:
    systems, interfaces, areas = ctx.data("ospf-system-all-vrfs") or {}, ctx.data("ospf-interfaces-all-vrfs"), ctx.data("ospf-areas") or {}
    runs = {vrf: ospf_runs(systems, interfaces, vrf) for vrf in systems}
    enabled = any(r for vrf, r in runs.items() if vrf != "0")
    for vrf in sorted(systems):
        s = systems[vrf] if isinstance(systems[vrf], dict) else {}
        if not runs[vrf] and (vrf != "0" or enabled):
            # ECOS fills in a router ID on disabled segments and default_rtmap_to_ospf is the default: only a map of the site's own is a setting
            kept = ["redistMapToOSPF {}".format(s["redistMapToOSPF"])] if s.get("redistMapToOSPF") not in (None, "", "default_rtmap_to_ospf") else []
            if kept:
                ctx.note("ospf-system-all-vrfs[{}]".format(vrf), "outside-preconfig", "segmentOspfConfig",
                         "segment {}: OSPF switched off with no interfaces, but settings are kept ({}); such a segment is not written, so the target keeps its own".format(ctx.segment(vrf, strict=False), ", ".join(kept)))
            else:
                ctx.note("ospf-system-all-vrfs[{}]".format(vrf), "default-omitted", "segmentOspfConfig", "segment {}: OSPF disabled with no interfaces, not written".format(ctx.segment(vrf, strict=False)))
        elif runs[vrf] and s and not s.get("enable") and enabled and isinstance((interfaces or {}).get(vrf, {}), dict) and interfaces is not None:
            ctx.note("ospf-system-all-vrfs[{}]".format(vrf), "mapped", "segmentOspfConfig", "segment {}: OSPF switched off but configured on interfaces; written with enable false".format(ctx.segment(vrf, strict=False)))
    if not enabled:
        ctx.note("ospf-system-all-vrfs", "default-omitted", "segmentOspfConfig", "0 non-default segments with OSPF")
        return None
    out = []
    for vrf in sorted(systems):
        if not runs[vrf]:
            continue
        try:
            s, ifs = systems[vrf], deployed(ctx, "ospf-interfaces-all-vrfs[{}]".format(vrf), "segmentOspfConfig.interfaces", block(interfaces, vrf))
            src_areas = sorted((areas.get(vrf) or {}).items())
            entry = {"segment": ctx.segment(vrf), "enable": s["enable"], "routerId": nul(s.get("routerId")), "redistMapToOspf": nul(s.get("redistMapToOSPF")), "opaqueEnable": s.get("opaque_enable"),
                     "areas": each(ctx, "ospf-areas[{}]".format(vrf), "segmentOspfConfig.areas", src_areas, ospf_area),
                     "interfaces": each(ctx, "ospf-interfaces-all-vrfs[{}]".format(vrf), "segmentOspfConfig.interfaces", sorted(ifs.items()), ospf_interface)}
            if (ifs and not entry["interfaces"]) or (src_areas and not entry["areas"]):  # an empty list would replace the target's on apply
                raise ValueError("no OSPF interface or area of the segment could be read")
            bfd = sorted(n for n, i in ifs.items() if isinstance(i, dict) and i.get("bfdDesired"))
        except ITEM_ERRORS as err:
            item_failed(ctx, "ospf-system-all-vrfs[{}]".format(vrf), "segmentOspfConfig", err)
            continue
        if bfd:
            ctx.note("ospf-interfaces-all-vrfs[{}]".format(vrf), "unmapped-source-key", "segmentOspfConfig.interfaces", "BFD is enabled on {} but segmentOspfConfig has no bfdEnabled field".format(", ".join(bfd)))
        out.append(entry)
    if out:
        ctx.note("ospf-system-all-vrfs", "mapped", "segmentOspfConfig", "{} segments with OSPF (includes Default when non-default segments use OSPF)".format(len(out)))
    return out or None


def configured_route(ctx: Ctx, prefix: Any, next_hop: Any, if_name: Any) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """The route as configured (subnets3/configured): (prefix entry with the advert flags, interface entry with the comment).
    /subnets has no comment and reports advert_bgp/advert_ospf as false."""
    entry = (((ctx.data("static-routes-configured") or {}).get("prefix") or {}).get(prefix) or {})
    return entry, ((((entry.get("nhop") or {}).get(next_hop or "") or {}).get("interface") or {}).get(if_name or "") or {})


def route_list(ctx: Ctx, entries: List[Dict[str, Any]], vrf: str, target: str = "localRoutes.routes") -> List[Dict[str, Any]]:
    out, failed = [], 0
    for e in entries:
        try:
            route = one_route(ctx, e, vrf, target)
        except ITEM_ERRORS as err:
            failed += 1
            item_failed(ctx, "subnets[{}] route {}".format(vrf, ((e.get("state") or {}) if isinstance(e, dict) else {}).get("prefix")), target, err)
            continue
        if route:
            out.append(route)
    if failed and not out:  # routes replace on apply: an empty list would remove the target's
        raise ValueError("no route of segment {} could be read".format(vrf))
    kept: List[Dict[str, Any]] = []
    for r in sorted(out, key=lambda r: (str(r.get("routeIpSubnet")), str(r.get("nextHop") or ""))):
        first = next((k for k in kept if (k["routeIpSubnet"], k["nextHop"], k["interfaceName"]) == (r["routeIpSubnet"], r["nextHop"], r["interfaceName"])), None)
        if first is None:
            kept.append(r)
            continue
        differ = sorted(k for k in set(r) | set(first) if r.get(k) != first.get(k))  # one route per prefix and next hop: the first in the source is written
        ctx.note("subnets", "mapped", target, "route {} next hop {}, segment {}: two source routes are the same once the interface is removed; written once{}".format(
            r["routeIpSubnet"], r["nextHop"], ctx.segment(vrf, strict=False) or vrf,
            " with the first one's {} (assumption: confirm the merged route's settings)".format(", ".join(differ)) if differ else ""))
    return kept


def one_route(ctx: Ctx, e: Dict[str, Any], vrf: str, target: str = "localRoutes.routes") -> Optional[Dict[str, Any]]:
    """One configured local route, or None when it is not written (the reason is ledgered)."""
    st = e["state"]
    if not (st.get("configured") and st.get("local")) or st.get("automatic"):
        return None
    conf = e.get("config") or {}
    if managed(conf) or managed(st):  # Orchestrator services (third-party cloud integrations, ...) create these themselves
        ctx.note("subnets", "orchestrator-managed", target, "skipped route {} created by Orchestrator (gms_marked)".format(st.get("prefix")))
        return None
    if not st.get("nextHop") and not st.get("ifName") and not conf:
        ctx.note("subnets", "unresolved", target, "route {} has neither next hop nor interface in its state and no route config, so it is not written".format(st.get("prefix")))
        return None
    # The state shows next hop 0.0.0.0 or :: as empty and the interface in use; the route's config keeps what was set ("default" is any interface)
    next_hop = st.get("nextHop") or conf.get("nextHop")
    cfg_if = conf.get("ifName") or st.get("ifName")
    if_name = None if cfg_if == "default" else cfg_if
    if not next_hop:  # apply rejects it: "Next Hop cannot be empty when interface is specified"
        ctx.note("subnets", "unresolved", target, "route {} on {} has no next hop; a preconfig route needs one, so it is not written".format(st.get("prefix"), if_name))
        return None
    if next_hop in ("0.0.0.0", "::") and if_name:  # the interface has no effect and ECOS 9.7+ rejects it on apply: removed, zone left as the source has it (docs/decisions/0016)
        ctx.note("subnets", "mapped", target, "route {} (segment {}): interface {} removed (next hop {} with an interface has no effect; ECOS 9.7+ rejects it); the route's zone "
                 "shows as none on the appliance, ECOS ignores a zone on a route without an interface (docs/decisions/0016)".format(st.get("prefix"), ctx.segment(vrf, strict=False) or vrf, if_name, next_hop))
        if_name = None
    zone_id = conf.get("zone_id", st.get("zone_id"))  # the state reports the zone of the interface in use
    zone = None if str(zone_id) in ("65534", "") else ctx.zone(vrf, zone_id)
    # subnets3/configured holds the Default segment only and ignores segment parameters (ECOS 9.6.2.1)
    cfg_prefix, cfg = configured_route(ctx, st["prefix"], next_hop, cfg_if) if vrf == "0" else ({}, {})
    route = {"routeIpSubnet": st["prefix"], "nextHop": nul(next_hop), "interfaceName": nul(if_name), "metric": st["metric"], "advertise": cfg_prefix.get("advert", st["advert"]),
             "advertiseToBgp": cfg_prefix.get("advert_bgp", st["advert_bgp"]), "advertiseToOspf": cfg_prefix.get("advert_ospf", st["advert_ospf"]), "zone": zone,
             "routeLabel": ctx.route_label(st.get("label"), "subnets", "route {}".format(st["prefix"]), target + ".routeLabel")}
    if vrf != "0":
        ctx.note("subnets-all-vrfs[{}]".format(vrf), "mapped", "segmentLocalRoutes.routes", "route {}: advertise flags taken from route state, which for Default routes disagrees with the configured table (assumption: confirm the flags)".format(st["prefix"]))
    for key, value in (("comment", cfg.get("comment") or conf.get("comment")), ("tag", cfg.get("dir") or conf.get("tag"))):  # subnets3 calls the tag dir, /subnets/all calls it tag
        if value:
            route[key] = value
    note_ref(ctx, "subnets", target + ".interfaceName", "route " + st["prefix"], if_name)
    return route


def sharing_source(ctx: Ctx) -> Optional[Dict[str, Any]]:
    """auto_subnet.vrf of /systemInfo/system; None, ledgered not-readable, when that read failed or has another shape: not "no settings"."""
    data = ctx.data("system-info")
    if data is None and not read_failed(ctx.cap, "system-info") and not any(i.get("id") == "system-info" and i.get("status") == "ok" for i in getattr(ctx.cap, "index", None) or []):
        return {}  # not captured, or absent (404); a read that failed, or came back null, is not "no settings"
    auto = (data.get("auto_subnet") if data.get("auto_subnet") is not None else {}) if isinstance(data, dict) else None
    vrfs = (auto.get("vrf") or {}) if isinstance(auto, dict) else None
    if not isinstance(vrfs, dict):
        ctx.note("system-info", "not-readable", "localRoutes, segmentLocalRoutes", "the subnet-sharing read (/systemInfo/system) failed or has an unexpected shape, so subnet-sharing settings "
                 "(advertise local LAN/WAN subnets, metric, communities, local ASN filter, route map) are not written and segments with only such settings are unknown; check them by hand")
        return None
    return vrfs or {}


def subnet_sharing(ctx: Ctx, vrf: str, target: str) -> Dict[str, Any]:
    """Subnet-sharing settings of one segment from /systemInfo/system auto_subnet (verified by live apply on ECOS 9.7.1)."""
    vrfs = sharing_source(ctx)
    if vrfs is None:
        return {}
    src = vrfs.get(vrf)
    # ECOS 9.6.2+ keeps no trace of useSharedSubnetInfo or the OSPF-to-subnet-share redistribution fields (route maps replaced them)
    ctx.note("system-info.auto_subnet", "default-omitted", target, "useSharedSubnetInfo, redistOspfToSubnetShare, ospfRedistMetric, ospfRedistTag are legacy fields that ECOS does not store (route maps replaced them): nothing to carry, the target keeps its defaults")
    if not src:
        return {}
    ctx.unmapped("system-info.auto_subnet.vrf[{}]".format(vrf), src, {"add_local_lan", "add_local_wan", "add_local_metric", "add_local_communities", "local_communities",
                                                                      "local_asn_filter", "rtmap_to_subshare", "add_local_asn"}, target)
    if src.get("add_local_asn"):
        ctx.note("system-info.auto_subnet.vrf[{}].add_local_asn".format(vrf), "outside-preconfig", target, "add_local_asn is on, and the preconfig format has no field for it: the target keeps its own setting")
    ctx.note("system-info.auto_subnet.vrf[{}]".format(vrf), "mapped", target, "subnet-sharing flags, metric, communities, route map")
    out = {"advertiseLocalLanSubnets": bool(src.get("add_local_lan")), "advertiseLocalWanSubnets": bool(src.get("add_local_wan")), "localMetric": int(src.get("add_local_metric") or 0),
           "localCommunities": (src.get("local_communities") or "") if src.get("add_local_communities") else "", "filterRoutesWithLocalASN": bool(src.get("local_asn_filter"))}
    if src.get("rtmap_to_subshare"):
        out["redistToSDwanFabricRouteMap"] = src["rtmap_to_subshare"]
    return out


# ECOS values of a non-Default segment that was never configured (lab, ECOS 9.6.2.1 and 9.7.1)
SEGMENT_SHARING_DEFAULTS = {"advertiseLocalLanSubnets": False, "advertiseLocalWanSubnets": False, "localMetric": 50, "localCommunities": "", "filterRoutesWithLocalASN": False}


def own_sharing(entry: Dict[str, Any]) -> bool:
    """The entry sets a route map or a subnet-sharing value other than the ECOS default of a non-Default segment."""
    return bool(entry.get("redistToSDwanFabricRouteMap")) or any(k in entry and entry[k] != v for k, v in SEGMENT_SHARING_DEFAULTS.items())


def note_no_route_map(ctx: Ctx, vrf: str, entry: Dict[str, Any], target: str) -> None:
    # Omitted, null and "" all become default_rtmap_to_subsh on apply, and "none" names a map that does not exist (ECOS 9.6.2.1 and 9.7.1)
    if "redistToSDwanFabricRouteMap" not in entry and set(entry) - {"segment", "routes"}:
        ctx.note("system-info.auto_subnet.vrf[{}]".format(vrf), "outside-preconfig", target + ".redistToSDwanFabricRouteMap",
                 "the source has no subnet-sharing route map; a preconfig cannot express that, so Orchestrator applies default_rtmap_to_subsh (denies 0.0.0.0/0 on the appliances checked): review the site")


def sharing_segments(ctx: Ctx) -> List[str]:
    """Segment IDs with subnet-sharing settings in /systemInfo/system auto_subnet."""
    return [vrf for vrf in sharing_source(ctx) or {} if ctx.segment(vrf, strict=False)]


def per_segment(ctx: Ctx) -> bool:
    """Routes go in segmentLocalRoutes when a non-Default segment has routes or subnet-sharing settings of its own."""
    all_vrfs = (ctx.data("subnets-all-vrfs") or {}).get("subnets") or {}
    return any(vrf != "0" for vrf in sharing_segments(ctx)) or any(vrf != "0" and has_routes(ctx, block, vrf) for vrf, block in all_vrfs.items())


def has_routes(ctx: Ctx, block: Any, vrf: str) -> bool:
    """Whether a segment has routes to write; an unreadable one counts as yes, so the per-segment pass writes the rest and ledgers it."""
    try:
        return bool(route_list(ctx, block.get("entries", []), vrf, "segmentLocalRoutes.routes"))
    except ITEM_ERRORS:
        return True


def routes_table(ctx: Ctx, ident: str) -> Optional[Dict[str, Any]]:
    """The "subnets" table of a routes read, or None when the read (or the table in it) could not be read."""
    raw = ctx.data(ident)
    table = raw.get("subnets") if isinstance(raw, dict) else None
    return table if isinstance(table, dict) else None


def m_localRoutes(ctx: Ctx) -> Optional[Dict[str, Any]]:
    if per_segment(ctx):
        if routes_table(ctx, "subnets-all-vrfs") is None and routes_table(ctx, "subnets") is None:  # segmentLocalRoutes ledgers both reads as not readable
            return None
        ctx.note("subnets", "default-omitted", "localRoutes", "non-default segments have routes or subnet-sharing settings, so the Default segment is written in segmentLocalRoutes (Orchestrator ignores localRoutes when segmentLocalRoutes is present)")
        return None
    subnets = routes_table(ctx, "subnets")
    if subnets is None:  # routes replace on apply: writing an empty list for an unread table would remove the target's routes
        ctx.note("subnets", "not-readable", "localRoutes.routes", "the routes read (/subnets) could not be read, live or cached, so localRoutes is not written; check the site's static routes by hand")
        return None
    try:
        routes = route_list(ctx, subnets.get("entries", []), "0")
    except ITEM_ERRORS as err:
        item_failed(ctx, "subnets", "localRoutes", err)
        return None
    flags = subnet_sharing(ctx, "0", "localRoutes")
    if not routes and not flags:
        ctx.note("subnets", "default-omitted", "localRoutes", "no locally configured routes")
        return None
    ctx.note("subnets", "mapped", "localRoutes.routes", "{} configured local routes (configured and local, not automatic or learned)".format(len(routes)))
    note_no_route_map(ctx, "0", flags, "localRoutes")
    return dict(flags, routes=routes)


def m_segmentLocalRoutes(ctx: Ctx) -> Optional[List[Dict[str, Any]]]:
    ctx.readable("vrfs")  # without segment names, "no segment has routes" cannot be told
    raw = routes_table(ctx, "subnets-all-vrfs")
    data = raw or {}
    if not per_segment(ctx):
        unread = [name for vrf, name in sorted(ctx.vrfs.items()) if vrf != "0"] if raw is None else []
        if unread:  # without /subnets/all, "no segment routes" cannot be told from "segment routes not read"
            ctx.note("subnets-all-vrfs", "not-readable", "segmentLocalRoutes.routes", "the per-segment routes read (/subnets/all) could not be read, so the routes of segment(s) {} are unknown and not written; check them by hand".format(", ".join(unread)))
        elif sharing_source(ctx) is None:  # no segment routes, but segments with subnet-sharing settings only cannot be told
            ctx.note("system-info", "not-readable", "segmentLocalRoutes", "no non-default segment has configured routes, but the subnet-sharing read failed, so segments with "
                     "only subnet-sharing settings are unknown and segmentLocalRoutes is not written; check them by hand")
        else:
            ctx.note("subnets-all-vrfs", "default-omitted", "segmentLocalRoutes", "0 non-default segments with configured routes or subnet-sharing settings")
        return None
    source = "subnets-all-vrfs"
    if raw is None:  # routes replace on apply: a segment whose routes were not read is left out, never written with an empty list
        default = routes_table(ctx, "subnets")  # the Default segment's configured routes, the same table localRoutes reads
        data = {"0": default} if default is not None else {}
        unread = [ctx.segment(v, strict=False) or v for v in sorted(sharing_segments(ctx)) if v not in data]
        ctx.note("subnets-all-vrfs", "not-readable", "segmentLocalRoutes.routes", "the per-segment routes read (/subnets/all) could not be read, so the routes of segment(s) {} are unknown and those segments are not written{}; check them by hand".format(
            ", ".join(unread) or "-", "; Default routes come from /subnets" if default is not None else ""))
        source = "subnets"
    out = []
    # A segment without routes still carries subnet-sharing settings of its own; one at the ECOS defaults is left out, since writing it adds default_rtmap_to_subsh
    for vrf in sorted(set(data) | set(sharing_segments(ctx))):
        if raw is None and vrf not in data:
            continue
        try:
            routes = route_list(ctx, block(data, vrf).get("entries", []), vrf, "segmentLocalRoutes.routes")
        except ITEM_ERRORS as err:
            item_failed(ctx, "subnets-all-vrfs[{}]".format(vrf), "segmentLocalRoutes", err)
            continue
        flags = subnet_sharing(ctx, vrf, "segmentLocalRoutes")
        if routes or (flags and (vrf == "0" or own_sharing(flags))):
            with guarded(ctx, "subnets-all-vrfs[{}]".format(vrf), "segmentLocalRoutes"):
                out.append(dict({"segment": ctx.segment(vrf)}, **flags, routes=routes))
                note_no_route_map(ctx, vrf, flags, "segmentLocalRoutes")
        elif flags:
            ctx.note("system-info.auto_subnet.vrf[{}]".format(vrf), "default-omitted", "segmentLocalRoutes",
                     "segment {} has no routes and its subnet-sharing settings are the ECOS defaults; writing it would add default_rtmap_to_subsh".format(ctx.segment(vrf, strict=False)))
    if out:
        ctx.note(source, "mapped", "segmentLocalRoutes", "{} segments with configured routes or subnet-sharing settings (Default included)".format(len(out)))
    return out or None


def m_pppoe(ctx: Ctx) -> Optional[Dict[str, Any]]:
    source = ctx.data("pppoe") or {}
    if not source:
        return None
    out = []
    for k, v in sorted(source.items()):
        entry = {"interfaceId": k, "userName": nul(v["USERNAME"]), "password": "<SECRET:not-captured>", "interfaceName": v["ETH"], "lcpFailCount": v["LCP-FAILURE"], "lcpInterval": v["LCP-INTERVAL"],
                 "dnsType": v["DNSTYPE"].lower()}
        if entry["dnsType"] == "specify":
            entry.update(dnsDomain1=v["DNS1"], dnsDomain2=v["DNS2"])
        entry.update(connectTimeout=v["CONNECT_TIMEOUT"], connectPoll=v["CONNECT_POLL"], serviceName=nul(v["SERVICENAME"]), acName=nul(v["ACNAME"]), defaultRoute=v["DEFAULTROUTE"])
        out.append(entry)
        ctx.unmapped("pppoe[{}]".format(k), v, {"USERNAME", "ETH", "LCP-FAILURE", "LCP-INTERVAL", "DNSTYPE", "DNS1", "DNS2", "CONNECT_TIMEOUT", "CONNECT_POLL", "SERVICENAME", "ACNAME", "DEFAULTROUTE"}, "pppoe")
    ctx.note("pppoe", "mapped", "pppoe", "{} sessions; the password is never read: it becomes an empty secret column".format(len(out)))
    return {"pppoeInterfaces": out}


def m_dhcpRemoteAddressPoolConfig(ctx: Ctx) -> Optional[Any]:
    raw = ctx.data("dhcp-remote-subnets") or []
    if not isinstance(raw, list) or not raw:
        return None
    source = [p for p in raw if isinstance(p, dict) and not p.get("interface")]
    if len(raw) > len(source):
        ctx.note("dhcp-remote-subnets", "default-omitted", "dhcpRemoteAddressPoolConfig", "{} local interface DHCP pool(s) omitted here (already mapped in deploymentInfo.dhcpInfo)".format(len(raw) - len(source)))
    if not source:
        return None
    pools = [{"dhcpAddressMask": p["subnet"], "scopeName": nul(p.get("scopeName")), "ipRange": p["ipRange"], "gatewayIp": p["gatewayIp"], "dnsServers": p["dnsServers"], "ntpServers": p["ntpServers"],
              "netbiosNameServers": p["netbiosNameServers"], "netbiosNodeType": p["netbiosNodeType"], "maxLeaseTime": p["maxLeaseTime"], "defaultLeaseTime": p["defaultLeaseTime"]} for p in source]
    options = pool_options(ctx, source[-1])
    if options:
        pools[-1]["options"] = options
    for p in source:
        ctx.unmapped("dhcp-remote-subnets", p, {"interface", "subnet", "scopeName", "ipRange", "gatewayIp", "dnsServers", "ntpServers", "netbiosNameServers", "netbiosNodeType", "maxLeaseTime", "defaultLeaseTime", "failover", "options"}, "dhcpRemoteAddressPoolConfig")
    ctx.note("dhcp-remote-subnets", "mapped", "dhcpRemoteAddressPoolConfig", "latest of {} remote pool(s)".format(len(pools)))
    if len(pools) > 1:
        ctx.note("dhcp-remote-subnets", "unresolved", "dhcpRemoteAddressPoolConfig", "{} more pool(s) not written: the validator rejects a list here (YAML format incorrect), so the preconfig holds one pool".format(len(pools) - 1))
    return pools[-1]


def pool_options(ctx: Ctx, pool: Dict[str, Any]) -> List[Dict[str, Any]]:
    """[{option, value}] of a remote pool. The API returns each option's value without its code (ECOS 9.7); the code is the key of the stored
    backup's /cn/dhcpd/config/subnet/<pool>/dhcp_options/<code> line, used only when the backup holds exactly the pool's option values."""
    raw = pool.get("options") or []
    src = []
    for i, o in enumerate(raw if isinstance(raw, list) else [raw]):  # one malformed option is ledgered and left out, never the whole pool
        if isinstance(o, dict) and "value" in o and str(o.get("option", 0)).isdecimal():
            src.append(o)
        else:
            ctx.note("dhcp-remote-subnets.options[{}]".format(i), "toolkit-error", "dhcpRemoteAddressPoolConfig.options",
                     "pool {} option {!r} not written: unexpected shape; a toolkit bug to report".format(pool["subnet"], o))
    if all("option" in o for o in src):
        return [{"option": int(o["option"]), "value": o["value"]} for o in src]
    found = (re.match(r"^internal set modify - /cn/dhcpd/config/subnet/(\S+)/dhcp_options/(\d+)/value value string (.*)$", l) for l in cli_lines(ctx))
    codes = sorted((int(m.group(2)), re.sub(r'^"(.*)"$', r"\1", m.group(3))) for m in found if m and m.group(1).replace("\\", "") == pool["subnet"])
    if sorted(v for _, v in codes) == sorted(str(o["value"]) for o in src):
        cli_note(ctx, "dhcpRemoteAddressPoolConfig.options", "DHCP option codes of pool {}".format(pool["subnet"]))
        return [{"option": code, "value": value} for code, value in codes]
    for o in src:
        ctx.note("dhcp-remote-subnets", "unresolved", "dhcpRemoteAddressPoolConfig.options", "pool {} option value {!r}: the API returns no option code and the stored backup does not hold "
                 "this pool's option values, so the pool's options are not written; set them by hand".format(pool["subnet"], o["value"]))
    return []


def m_interfaceConfig(ctx: Ctx) -> Optional[Dict[str, Any]]:
    info = (ctx.data("interface-state") or {}).get("ifInfo") or []
    out = []
    for i in info:
        name = i["ifname"]
        if name == "mgmt0" and not i.get("admin"):  # mgmt1 down is the usual state: not ledgered
            ctx.note("interface-state[mgmt0]", "outside-preconfig", "interfaceConfig", "mgmt0 is admin down; management ports are never carried (the management plane stays as the target has it)")
        if not re.match(r"^(lan|wan|tlan|twan|twlan|blan|bwan)\d+$", name):
            continue
        if i.get("ifSpeed") in ("auto", "") and i.get("ifDuplex") in ("auto", "") and i.get("admin"):  # "": a bonded blanN/bwanN has no speed of its own
            continue
        speed = i.get("ifSpeed")
        if speed != "auto" and not str(speed).isdigit():
            ctx.note("interface-state[{}]".format(name), "unresolved", "interfaceConfig.interfaces", "speed {!r} is neither auto nor a number; interface not written".format(speed))
            continue
        entry = {"interfaceName": name, "interfaceSpeed": speed if speed == "auto" else int(speed), "interfaceDuplex": i["ifDuplex"], "admin": "up" if i["admin"] else "down"}
        out.append(entry)
    if not out:
        ctx.note("interface-state", "default-omitted", "interfaceConfig", "every LAN and WAN interface is admin up with auto speed and duplex (management ports are not carried)")
        return None
    ctx.note("interface-state", "mapped", "interfaceConfig", "{} interfaces differ from auto/auto/up; the rest are omitted (section behaviour: replace)".format(len(out)))
    return {"interfaces": out}


def cli_lines(ctx: Ctx) -> List[str]:
    """Command lines of the newest stored backup's running configuration (can be older than the live configuration)."""
    what = "settings read from the stored backup's CLI lines (pass-through cap, flow redirection, ...) are not carried"
    if failed_read(ctx, "running-config", what):
        return []
    backup = ctx.data("running-config") or {}
    text = (backup.get("runningConfig") or "") if isinstance(backup, dict) else None
    if not isinstance(text, str):
        unreadable_read(ctx, "running-config", what)
        return []
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


def passthrough_max_bandwidth(lines: List[str]) -> Optional[int]:
    """Outbound shaping cap for pass-through traffic in kbps, from 'interface pass-through max-bandwidth N' (no API read holds it)."""
    return next((int(m.group(1)) for l in lines for m in [re.match(r"^interface pass-through max-bandwidth (\d+)$", l)] if m), None)


def cli_note(ctx: Ctx, target: str, what: str) -> str:
    backup = ctx.data("running-config") or {}
    ctx.note("running-config", "mapped", target, "{}; source is the stored backup of {} (backupTime {}), which may differ from the live configuration".format(what, backup.get("fileName"), backup.get("backupTime")))
    return target


def m_managementIp(ctx: Ctx) -> Optional[Dict[str, Any]]:
    mgmt0 = ((ctx.data("deployment") or {}).get("mgmtIfData") or {}).get("mgmt0") or {}
    if mgmt0.get("dhcp"):
        ctx.note("deployment.mgmtIfData.mgmt0", "runtime", "managementIp", "mgmt0 uses DHCP; managementIp is omitted so DHCP management is preserved")
        return None
    for line in cli_lines(ctx):
        m = re.match(r"^ip mgmt-ip (\S+)$", line)
        if m:
            cli_note(ctx, "managementIp", "ip mgmt-ip")
            return {"ipAddress": m.group(1)}
    return None


def m_peerPriority(ctx: Ctx) -> Optional[Dict[str, Any]]:
    peers = (ctx.data("peer-priority") or {}).get("peerlist") or {}
    if not peers:
        return None
    ctx.note("peer-priority", "mapped", "peerPriority", "{} peers; priority = peer_weight (the documented range is 1-1023 and peer_metric is 0); peer_metric not mapped (assumption)".format(len(peers)))
    return {"peerPriorities": [{"peerName": k, "priority": v["peer_weight"]} for k, v in sorted(peers.items())]}


def m_appExpressGroups(ctx: Ctx) -> Optional[List[str]]:
    names = sorted({a["appExpressGroupName"] for a in ctx.data("appexpress-group-association") or [] if a["nePk"] == ctx.nepk})
    if not names:
        return None
    ctx.note("appexpress-group-association", "mapped", "appExpressGroups", "{} groups".format(len(names)))
    return names


def m_thirdPartyServicesAssociation(ctx: Ctx) -> Optional[Dict[str, Any]]:
    flags = {}
    for key, ident in (("zscalerAssociation", "zscaler-association"), ("netskopeAssociation", "netskope-association"), ("axisAssociation", "axis-association")):
        flags[key] = any(e.get("nePk") == ctx.nepk for e in (ctx.data(ident) or {}).get("enabled", []))
    if not any(flags.values()):
        ctx.note("zscaler/netskope/axis-association", "default-omitted", "thirdPartyServicesAssociation", "no third-party service associated (an omitted flag leaves the association unchanged)")
        return None
    ctx.note("zscaler/netskope/axis-association", "mapped", "thirdPartyServicesAssociation", "booleans from the Orchestrator association lists; connectorService and serviceProviderAssociation have no source and are omitted")
    return flags


def m_multicast(ctx: Ctx) -> Optional[List[Dict[str, Any]]]:
    source, enable = ctx.data("multicast-config"), ctx.data("multicast-enable")
    one = isinstance(source, dict)  # ECOS before 9.7 (seen on 9.5.7 and 9.6.4): one object without vrf_id, and enable as {"enable": ...}
    if one:
        on = enable.get("enable") if isinstance(enable, dict) and isinstance(enable.get("enable"), bool) else None
        configured = any(source.get(k) for k in ("rp", "pim", "igmp", "filter_name"))
        if on is None:  # a missing or odd enable read is not "disabled"
            ctx.note("multicast-enable", "not-readable", "multicast" if not configured else "multicast.enable", "the multicast enable read is missing or has an unexpected shape, so whether "
                     "multicast is on is unknown; {}; check it by hand".format("multicast is not written" if not configured else "enable is written as none"))
            if not configured:
                return None
        elif not on and not configured:
            ctx.note("multicast-config", "default-omitted", "multicast", "multicast disabled and not configured")
            return None
        source, enable = [dict(source, vrf_id=0)], [{"vrf_id": 0, "enable": on}]
    if not isinstance(source, list):
        if source:
            ctx.note("multicast-config", "unresolved", "multicast", "the multicast read has an unexpected shape ({}), not written".format(type(source).__name__))
        return None
    flags = {str(e.get("vrf_id")): e.get("enable") for e in (enable or []) if isinstance(e, dict)}
    known = set()
    for m in ctx.mode_ifs():
        for a in m["applianceIPs"]:
            vlan = int(a.get("vlan") or 0)
            known |= {"{}.{}".format(m["ifName"], vlan) if vlan > 0 else m["ifName"], m["ifName"], ctx.label(a["label"])}
    known |= set((ctx.data("loopbacks") or {}).keys())
    out = []
    for seg in source:
        try:
            enabled = flags.get(str(seg["vrf_id"]))
            for stale in sorted(k for k in (seg.get("pim") or {}) if k not in known):
                if re.match(r"^pim\d+$", stale):  # 'interface pimN virtual pim' in the running-config; the 9.7 list read does not report them
                    ctx.note("multicast-config", "runtime", "multicast.pim", "pim entry '{}' is a virtual PIM interface, not an interface or label a preconfig can name; not written".format(stale))
                    continue
                ctx.note("multicast-config", "runtime", "multicast.pim", "pim entry '{}' matches no interface or label of this appliance (stale); the validator rejects it".format(stale))
            pim = [{"interfaceName": k, "pimEnable": v["enable"], "igmpEnable": bool((seg.get("igmp") or {}).get(k, {}).get("enable")), "drPriority": v["dr_priority"], "helloInterval": v["hello_interval"],
                    "joinPruneInterval": v["join_prune_interval"]} for k, v in sorted((seg.get("pim") or {}).items()) if k in known]
            out.append({"segment": ctx.segment(seg["vrf_id"]), "enable": "true" if enabled else "false" if enabled is not None else "none", "rpAddresses": nul(seg.get("rp")),
                        "filterName": nul(seg.get("filter_name")), "pim": pim})
            ctx.unmapped("multicast-config", seg, {"vrf_id", "rp", "pim", "igmp", "filter_name"}, "multicast")
        except ITEM_ERRORS as err:
            item_failed(ctx, "multicast-config[{}]".format(seg.get("vrf_id") if isinstance(seg, dict) else seg), "multicast", err)
            continue
    if source and not out:  # every segment failed (ledgered above); an empty source list is written as before
        return None
    ctx.note("multicast-config", "mapped", "multicast", "{} segment(s); igmpEnable true when the interface is listed under igmp (assumption); enable written as a string true/false/none".format(len(out)))
    if one:
        ctx.note("multicast-config", "mapped", "multicast", "one object without segment (ECOS before 9.7), written as the Default segment (assumption: multicast before 9.7 is not per segment)")
    return out


def vrrp_prio(act: Dict[str, Any], type_key: str) -> Dict[str, Any]:
    """A vrrp-prio action carries its delta as dec or inc."""
    direction = "decrease" if act.get("dec") is not None else "increase"
    return {type_key: direction + "VRRPPriority", "interfaceName": act.get("port-label") or act.get("port-name"), "priority": int(act.get("dec") if direction == "decrease" else act.get("inc"))}


def probe_tunnel(ctx: Ctx, ifname: str) -> Optional[str]:
    """The one user passthrough tunnel whose local IP is on interface ifname, else None."""
    ips = {a.get("ip") for m in ctx.mode_ifs() for a in m.get("applianceIPs", [])
           if a.get("ip") and ("{}.{}".format(m["ifName"], int(a.get("vlan") or 0)) if int(a.get("vlan") or 0) > 0 else m["ifName"]) == ifname}
    names = [t["alias"] for t in (ctx.data("passthrough-tunnels") or {}).values() if not managed(t) and t.get("sourceIpAddress") in ips]
    return names[0] if len(names) == 1 else None


def m_ipSlaRule(ctx: Ctx) -> Optional[Dict[str, Any]]:
    source = ctx.data("ipsla-managers") or {}
    mine = {k: v for k, v in source.items() if not managed(v)}
    if len(source) > len(mine):
        ctx.note("ipsla-managers", "orchestrator-managed", "ipSlaRule", "{} rules generated by Orchestrator services (gms_marked)".format(len(source) - len(mine)))
    if not mine:
        return None
    down_str = {"alarm": "raiseAlarm", "no-sub-share": "disableSubnetSharing"}
    up_str = {"def-alarm": "clearAlarm", "def-subnet": "defaultSubnetAction", "def-vrrp": "defaultVRRP"}
    rules = []
    for k, v in sorted(mine.items()):
        try:
            op = next(iter(v["operation"].values()))
            op_type = op.get("type", "ip-monitor")
            if op_type == "port-monitor":
                monitor: Dict[str, Any] = {"monitorType": "interface", "interfaceName": op.get("port-label") or op.get("port-name")}
            elif op_type == "vrrp-monitor":
                monitor = {"monitorType": "vrrp", "interfaceName": op.get("port-label") or op.get("port-name")}
            elif op_type == "http-monitor":
                monitor = {"monitorType": "http/https", "urls": [u.strip() for u in str(op.get("http-monitor-url") or "").split(",") if u.strip()],
                           "httpRequestTimeout": int(op.get("http-timeout", 60)), "keepAlive": int(op.get("ka", 1)), "samplingWindow": int(op.get("sample-int", 300)),
                           "monitorUpThreshold": int(op.get("up-thresh", 3)), "monitorDownThreshold": int(op.get("dn-thresh", 30)),
                           "monitorUpLossThreshold": int(op.get("loss-up-thresh", 0)), "monitorDownLossThreshold": int(op.get("loss-dn-thresh", 0)),
                           "monitorUpLatencyThreshold": int(op.get("rtt-up-thresh", 0)), "monitorDownLatencyThreshold": int(op.get("rtt-dn-thresh", 0)),
                           "metricCombination": op.get("metric-combination", "metric-or")}
                if op.get("port-label") or op.get("port-name"):
                    monitor["interfaceName"] = op.get("port-label") or op.get("port-name")
                if op.get("proxyAddress"):
                    monitor.update({"proxyAddress": op["proxyAddress"], "proxyPort": int(op.get("proxyPort") or 0)})
                if op.get("user-agent"):
                    monitor["userAgent"] = op["user-agent"]
            else:
                monitor = {"monitorType": "ping", "ipAddress": op.get("ip-monitor-ip"), "keepAlive": int(op.get("ka", 1)), "samplingWindow": int(op.get("sample-int", 300)),
                           "monitorUpThreshold": int(op.get("up-thresh", 3)), "monitorDownThreshold": int(op.get("dn-thresh", 30)),
                           "monitorUpLossThreshold": int(op.get("loss-up-thresh", 0)), "monitorDownLossThreshold": int(op.get("loss-dn-thresh", 0)),
                           "monitorUpLatencyThreshold": int(op.get("rtt-up-thresh", 0)), "monitorDownLatencyThreshold": int(op.get("rtt-dn-thresh", 0)),
                           "metricCombination": op.get("metric-combination", "metric-or")}
                if op.get("port-label") or op.get("port-name"):
                    monitor["interfaceName"] = op.get("port-label") or op.get("port-name")
                if op.get("tunnel-name"):
                    monitor["tunnelName"] = op["tunnel-name"]
                if op.get("src-port-label") or op.get("src-port-name"):
                    monitor["sourceInterfaceName"] = op.get("src-port-label") or op.get("src-port-name")
                    note_ref(ctx, "ipsla-managers[{}]".format(k), "ipSlaRule.ipslaMonitor.sourceInterfaceName", "IP SLA rule " + k, monitor["sourceInterfaceName"])
                if str(op.get("force-dns")).lower() == "true":
                    monitor["forceDnsThroughProbePath"] = True
                if monitor.get("sourceInterfaceName") and not monitor.get("interfaceName") and not monitor.get("tunnelName"):
                    tunnel = probe_tunnel(ctx, monitor["sourceInterfaceName"])
                    if not tunnel:
                        ctx.note("ipsla-managers[{}]".format(k), "unresolved", "ipSlaRule", "probe sourced from {} names no interface or tunnel and no single passthrough tunnel is sourced there; rule not written (the validator requires one)".format(monitor["sourceInterfaceName"]))
                        continue
                    monitor["tunnelName"] = tunnel
                    ctx.note("ipsla-managers[{}]".format(k), "mapped", "ipSlaRule.ipslaMonitor.tunnelName", "the appliance stores no tunnel for a tunnel-sourced probe; {} is the only passthrough tunnel sourced from {} (assumption)".format(tunnel, monitor["sourceInterfaceName"]))
            dn_raw = v.get("downAction")
            if isinstance(dn_raw, dict) and dn_raw:
                act = next(iter(dn_raw.values()))
                if act.get("type") == "subnet-metric":
                    down_act: Dict[str, Any] = {"downActionType": "modifySubnetMetric", "subnetMetricDelta": int(act["delta"])}
                elif act.get("type") in ("tun-dn", "tun-up"):
                    down_act = {"downActionType": "disableTunnel" if act["type"] == "tun-dn" else "enableTunnel", "tunnelName": act["tun-alias"]}
                elif act.get("type") == "subnet-adv":  # the appliance keeps no priority for this action
                    down_act = {"downActionType": "advertiseSubnet", "interfaceName": act.get("port-label") or act.get("port-name")}
                elif act.get("type") == "vrrp-prio":
                    down_act = vrrp_prio(act, "downActionType")
                elif act.get("type") == "subnet-share":
                    down_act = {"downActionType": "disableSubnetSharing"}
                elif act.get("type") == "subnet-rmv":
                    down_act = {"downActionType": "removeAutoSubnet", "interfaceName": act.get("port-label") or act.get("port-name")}
                else:
                    ctx.note("ipsla-managers[{}]".format(k), "unresolved", "ipSlaRule.downAction", "down action type {} has no mapping, written as raiseAlarm".format(act.get("type")))
                    down_act = {"downActionType": "raiseAlarm"}
            else:
                down_act = {"downActionType": down_str.get(str(dn_raw), "raiseAlarm")}
            up_raw = v.get("upAction")
            if isinstance(up_raw, dict) and up_raw:
                act = next(iter(up_raw.values()))
                if act.get("type") in ("tun-up", "tun-dn"):
                    up_act: Dict[str, Any] = {"upActionType": "enableTunnel" if act["type"] == "tun-up" else "disableTunnel", "tunnelName": act["tun-alias"]}
                elif act.get("type") == "vrrp-prio":
                    up_act = vrrp_prio(act, "upActionType")
                else:
                    ctx.note("ipsla-managers[{}]".format(k), "unresolved", "ipSlaRule.upAction", "up action type {} has no mapping, written as clearAlarm".format(act.get("type")))
                    up_act = {"upActionType": "clearAlarm"}
            else:
                up_act = {"upActionType": up_str.get(str(up_raw), "clearAlarm")}
            rules.append({"enable": v["enable"], "samplingInterval": int(v["interval"]), "comment": nul(v["comment"]), "routeLabel": ctx.route_label(v.get("routeLabelId"), "ipsla-managers[{}]".format(k), "IP SLA rule {}".format(k), "ipSlaRule.routeLabel"),
                          "ipslaMonitor": monitor, "downAction": down_act, "upAction": up_act})
        except ITEM_ERRORS as err:
            item_failed(ctx, "ipsla-managers[{}]".format(k), "ipSlaRule", err)
            continue
    rules.sort(key=lambda r: (str(r["ipslaMonitor"].get("monitorType")), str(r["ipslaMonitor"].get("interfaceName") or ""), str(r["ipslaMonitor"].get("ipAddress") or r["ipslaMonitor"].get("urls") or "")))
    if not rules:
        return None
    ctx.note("ipsla-managers", "mapped", "ipSlaRule", "{} user rules (ping, interface, vrrp, http/https monitors)".format(len(rules)))
    return {"ruleEntries": rules}


IDS_MODES = {"disabled": "Off", "ids": "IDS Only", "ips_lookaside": "IPS-Performant", "ips_inline": "IPS-Inline"}


def m_idsIpsConfig(ctx: Ctx) -> Optional[Dict[str, Any]]:
    profiles = ctx.data("ids-profile-state") or {}
    mine = [name for name, nodes in profiles.items() if ctx.nepk in nodes]
    if not mine:
        return None
    # GET /ids/state lists nePks per mode; an appliance in no list has an unknown mode. Guessing "Off" would switch IDS/IPS off (replace section).
    state = ctx.data("ids-state") or {}
    mode = next((IDS_MODES[k] for k in IDS_MODES if ctx.nepk in (state.get(k) or [])), None)
    if mode is None:
        ctx.note("ids-state", "unresolved", "idsIpsConfig", "not written: profile is {!r} but the appliance is in no /ids/state list, so its IDS/IPS mode is unknown. Orchestrator lists only appliances whose IDS/IPS was set from Orchestrator; "
                 "unlisted ones checked on a reference Orchestrator had never turned IDS/IPS on, and leaving the section out keeps the new appliance's default (off)".format(mine[0]))
        return None
    ctx.note("ids-profile-state", "mapped", "idsIpsConfig.profile", "profile name from the assignment list: {} (suffix such as _S5 is part of the stored name; the preconfig example uses 'Default')".format(mine[0]))
    ctx.note("ids-state", "mapped", "idsIpsConfig.mode", "{} (list-to-mode mapping from the Swagger idsStateGet descriptions; all four modes verified by live apply and re-read on ECOS 9.7.1)".format(mode))
    return {"mode": mode, "profile": mine[0]}


def m_flowRedirection(ctx: Ctx) -> Optional[Dict[str, Any]]:
    clusters = ctx.data("cluster-state") or {}
    if isinstance(clusters, dict):
        for site_blk in clusters.values():
            app_if = ((site_blk or {}).get("siteApplianceInterfaceIps") or {}).get(ctx.nepk)
            if isinstance(app_if, dict) and isinstance(app_if.get("state"), dict):
                st = app_if["state"]
                iface = st.get("interface") or app_if.get("interfaceName")
                peers = [p["peerIP"] for p in (st.get("peerIPStatusList") or []) if isinstance(p, dict) and p.get("peerIP")]
                if iface and "." in str(iface):
                    ctx.note("cluster-state", "orchestrator-managed", "flowRedirection", "cluster subinterface '{}' is the EdgeHA sync interface (created by haConfig), not standalone flowRedirection".format(iface))
                    return None
                if peers and iface:
                    ctx.note("cluster-state", "mapped", "flowRedirection", "{} cluster peer(s) on {}".format(len(peers), iface))
                    return {"enable": bool(st.get("flow_redir", True)), "waitTime": int(st.get("wait_time", 0)), "interfaceName": iface, "peers": [{"peerIp": p} for p in peers]}
    lines = cli_lines(ctx)
    peers = [m.group(1) for l in lines for m in [re.match(r"^cluster peer (\S+)$", l)] if m]
    iface = next((m.group(1) for l in lines for m in [re.match(r"^cluster interface (\S+)$", l)] if m), None)
    # ECOS prints no wait-time line at its default; 50 is the base template default (lab: pushed 50, backup had no line)
    wait = next((int(m.group(1)) for l in lines for m in [re.match(r"^flow-redirection wait-time (\d+)$", l)] if m), 50)
    if not peers:
        if iface:
            ctx.note("running-config", "default-omitted", "flowRedirection", "cluster interface {} without peers (dormant)".format(iface))
        return None
    if iface and "." in iface:
        ctx.note("running-config", "orchestrator-managed", "flowRedirection", "cluster subinterface '{}' is the EdgeHA sync interface (created by haConfig), not standalone flowRedirection".format(iface))
        return None
    cli_note(ctx, "flowRedirection", "cluster peers, interface and wait time; enable is true because peers are configured (assumption)")
    return {"enable": True, "waitTime": wait, "interfaceName": iface, "peers": [{"peerIp": p} for p in peers]}


def m_vxlan(ctx: Ctx) -> Optional[Dict[str, Any]]:
    live = ctx.data("vxlan") or {}
    seg_map = ctx.data("vxlan-vni-map") or {}
    if isinstance(live, dict) and live.get("vtepIf") and isinstance(seg_map, dict):
        maps = []
        for seg_id, v in sorted(seg_map.items(), key=lambda kv: num_key(kv[0])):
            vni_val = (v or {}).get("vni")
            if str(vni_val) in ("None", "", "0", "-1", "4294967295"):
                continue
            try:
                maps.append({
                    "vni": int(vni_val),
                    "segment": ctx.segment(seg_id),
                    "zone": ctx.zone(seg_id, v.get("zoneId", 0)),
                    "role": ctx.role(v.get("role", 0)) or "default",
                })
            except Unresolved as err:
                item_failed(ctx, "vxlan-vni-map[{}]".format(seg_id), "vxlan", err)
        maps.sort(key=lambda x: int(x["vni"]))
        ctx.note("vxlan, vxlan-vni-map", "mapped", "vxlan", "vtep interface {} and {} VNI map(s)".format(live["vtepIf"], len(maps)))
        note_ref(ctx, "vxlan", "vxlan.vtepSrcInterface", "the VXLAN VTEP", live["vtepIf"])
        return {"destinationUdpPort": int(live.get("port", 4789)), "vtepSrcInterface": live["vtepIf"], "vniVrfMaps": maps}
    lines = cli_lines(ctx)
    vtep = next((m.group(1) for l in lines for m in [re.match(r"^vxlan vtep-interface (\S+)$", l)] if m), None)
    if not vtep:
        dormant = ["{} {}".format(ctx.segment(k, strict=False) or k, v.get("vni")) for k, v in sorted(seg_map.items(), key=lambda kv: str(kv[0]))
                   if isinstance(v, dict) and str(v.get("vni")) not in ("None", "", "0", "-1", "4294967295")] if isinstance(seg_map, dict) else []
        if dormant and not lines and not (isinstance(live, dict) and "vtepIf" in live):  # no readable backup: its VTEP line is unknown
            ctx.note("vxlan-vni-map", "not-readable", "vxlan", "VNI maps ({}), but the VTEP interface could not be read (no /vxlan and no running-config), so they are not written; check by hand".format(", ".join(dormant)))
        elif dormant:  # vtepSrcInterface is required by the format, so the maps cannot be written on their own
            ctx.note("vxlan-vni-map", "outside-preconfig", "vxlan", "VNI maps ({}) but no VTEP interface: the format requires vtepSrcInterface, so they are not written; the target keeps its own".format(", ".join(dormant)))
        elif seg_map and not isinstance(seg_map, dict):
            ctx.note("vxlan-vni-map", "unresolved", "vxlan", "VNI maps read in an unexpected shape ({}), not written".format(type(seg_map).__name__))
        return None
    vni: Dict[str, Dict[str, Any]] = {}
    for l in lines:
        m = re.match(r"^vxlan segment (\S+) (vni|zone|role-id) (\d+)$", l)
        if m and m.group(3) != "4294967295":
            vni.setdefault(m.group(1), {})[m.group(2)] = int(m.group(3))
    if vni:
        ctx.readable("vrfs")  # the CLI names segments: their zone ids resolve per segment id
    maps = sorted([{"vni": v["vni"], "segment": seg, "zone": ctx.zone(next((k for k, n in ctx.vrfs.items() if n == seg), "0"), v.get("zone", 0)), "role": ctx.role(v.get("role-id", 0)) or "default"} for seg, v in sorted(vni.items()) if "vni" in v], key=lambda x: int(x["vni"]))
    cli_note(ctx, "vxlan", "vtep interface and VNI maps")
    note_ref(ctx, "vxlan", "vxlan.vtepSrcInterface", "the VXLAN VTEP", vtep)
    return {"destinationUdpPort": live.get("port", 4789), "vtepSrcInterface": vtep, "vniVrfMaps": maps}


def m_ecLicensing(ctx: Ctx) -> Optional[Dict[str, Any]]:
    lines = cli_lines(ctx)
    boost = next((int(m.group(1)) for l in lines for m in [re.match(r"^system eclicense boost bandwidth (\d+)$", l)] if m), None)
    if boost is None or "system eclicense boost enable" not in lines:
        return None
    ctx.note("running-config", "unresolved", "ecLicensing.bandwidthLevel", "the tier name for bandwidthLevel is not documented; only the boost bandwidth is mapped")
    cli_note(ctx, "ecLicensing", "boost bandwidth; useDefaultAccount true is an assumption (the validator requires either it or an account name and key)")
    return {"useDefaultAccount": True, "boost": boost}


def m_managementRoutes(ctx: Ctx) -> Optional[Dict[str, Any]]:
    routes = []
    for l in cli_lines(ctx):
        m = re.match(r"^ip default-gateway (\S+) (mgmt\d) (\d+)(?: (\S+))?$", l)
        if m:
            routes.append({"routeIpSubnet": "0.0.0.0/0", "nextHop": m.group(1), "interfaceName": m.group(2), "metric": int(m.group(3)), "sourceIp": m.group(4)})
        m = re.match(r"^ip route (\S+) /(\d+) (\S+) (mgmt\d) (\d+)(?: (\S+))?$", l)
        if m:
            routes.append({"routeIpSubnet": "{}/{}".format(m.group(1), m.group(2)), "nextHop": m.group(3), "interfaceName": m.group(4), "metric": int(m.group(5)), "sourceIp": m.group(6)})
    routes = [r for i, r in enumerate(routes) if r not in routes[:i]]  # the running config can list one route twice
    if not routes:
        return None
    cli_note(ctx, "managementRoutes", "{} management route(s); positional meaning gateway, interface, metric, source IP is an assumption".format(len(routes)))
    return {"routes": routes}


def factory_nac(src: Dict[str, Any]) -> bool:
    """NAC off and holding only what ECOS creates: objects named "default", a server at 0.0.0.1 (or none) with no key, trusted interfaces only."""
    objs = [o for k in ("server", "serverGroup", "aaaProfile", "dot1x", "macAuthProfile") for o in (src.get(k) or {}).values()]
    return (src.get("nacEnable") is False and all(o.get("name") == "default" for o in objs)
            and all(s.get("address") in ("0.0.0.1", "", None) and s.get("key") in ("", None) for s in src["server"].values())
            and all(p.get("auth_type") == 0 and p.get("profile") == "none" for p in ((src.get("applyPolicies") or {}).get("if") or {}).values()))


def m_nac(ctx: Ctx) -> Optional[Dict[str, Any]]:
    src = ctx.data("nac")
    if not src or not src.get("server"):
        return None
    if factory_nac(src):  # written, its empty server key fails /validate ("NAC - server key can not be empty"), and there is nothing to carry
        ctx.note("nac", "default-omitted", "nac", "NAC is disabled and holds only its factory-default objects")
        return None
    def rows(block: Dict[str, Any], rename: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        out = []
        for k, v in sorted(block.items(), key=lambda kv: int(kv[0])):
            row = {"id": int(k)}
            for key, value in v.items():
                if key in ("self", "stats_timeout", "name_") :
                    continue
                row[(rename or {}).get(key, key)] = nul(value) if isinstance(value, str) else value
            out.append(row)
        return out
    name_by_if = {}
    dep = ctx.data("deployment") or {}
    ctx.readable("ifLabels")
    lan_labels = {str(l["id"]): l["name"] for l in ((dep.get("sysConfig") or {}).get("ifLabels") or {}).get("lan") or []}
    for m in ctx.mode_ifs():
        for a in m["applianceIPs"]:
            vlan = int(a.get("vlan") or 0)
            # NAC takes LAN labels only; the appliance also keeps trusted entries for WAN interfaces
            name_by_if["{}.{}".format(m["ifName"], vlan) if vlan > 0 else m["ifName"]] = None if a.get("wanSide") else lan_labels.get(str(a.get("label")))
    # /validate accepts only ", " between names (2026-10-18); entry order kept, it may be the server priority
    groups = [{"id": int(k), "name": v["name"], "server": ", ".join(x["name"] for _, x in sorted(v["server"].items(), key=lambda kv: int(kv[0]))) if isinstance(v["server"], dict) else v["server"]} for k, v in sorted((src.get("serverGroup") or {}).items(), key=lambda kv: int(kv[0]))]
    policies = []
    skipped = 0
    for ifname, v in sorted(((src.get("applyPolicies") or {}).get("if") or {}).items()):
        trusted = v.get("auth_type") == 0 or v.get("profile") in ("none", "", None)  # the appliance stores profile "default" on trusted entries it applied without one
        if not name_by_if.get(ifname):  # auth_interface must be a LAN label; the appliance can keep policies for deleted interfaces
            if trusted:
                skipped += 1
            else:
                ctx.note("nac applyPolicies[{}]".format(ifname), "unresolved", "nac.applyPolicies[].auth_interface", "{} has no LAN label or no longer exists; policy not written".format(ifname))
            continue
        entry = {"auth_interface": name_by_if[ifname], "profile": None if trusted else v["profile"], "auth_type": {0: "trusted", 1: "both", 2: "802.1x", 3: "mac"}.get(v.get("auth_type"), v.get("auth_type"))}
        if trusted:
            del entry["profile"]  # /validate rejects profile "none" and accepts the key left out (2026-10-18)
        same = [p for p in policies if p["auth_interface"] == entry["auth_interface"]]
        if not same:
            policies.append(dict({"id": len(policies) + 1}, **entry))
        elif {k: x for k, x in same[0].items() if k != "id"} != entry:  # /validate rejects a label twice ("Duplicate lan label interfaces")
            ctx.note("nac applyPolicies[{}]".format(ifname), "unresolved", "nac.applyPolicies[].auth_interface", "{} shares label {} with an interface that has a different policy; only the first is written".format(ifname, entry["auth_interface"]))
    if skipped:
        ctx.note("nac applyPolicies", "default-omitted", "nac.applyPolicies", "{} WAN or unlabelled interfaces without an AAA profile".format(skipped))
    if policies:
        ctx.note("nac applyPolicies", "mapped", "nac.applyPolicies[].auth_type", "numeric auth_type codes to trusted/both/802.1x/mac are an assumption (0..3 in that order); auth_interface expects a label")
    out = _nac_fix(ctx=ctx, name_by_if=name_by_if, out={"nacEnable": src["nacEnable"], "dot1x": rows((src.get("dot1x") or {})), "macAuthProfile": rows((src.get("macAuthProfile") or {})), "server": rows(src["server"], {"address": "host"}),
                   "serverGroup": groups, "aaaProfile": rows((src.get("aaaProfile") or {})), "applyPolicies": policies})
    sources = {server.get("source_ip_interface") for server in out["server"]}
    kept = [p for p in policies if not (p["auth_type"] == "trusted" and p["auth_interface"] in sources)]
    if len(kept) < len(policies):  # /validate rejects a label used as both auth_interface and source_ip_interface
        ctx.note("nac applyPolicies", "default-omitted", "nac.applyPolicies", "trusted entry on the RADIUS server's source label {} (trusted is the appliance default)".format(", ".join(sorted({p["auth_interface"] for p in policies if p not in kept}))))
    out["applyPolicies"] = [dict(p, id=i + 1) for i, p in enumerate(kept)]
    empty = [k for k in ("dot1x", "macAuthProfile", "server", "serverGroup", "aaaProfile", "applyPolicies") if not out[k]]
    if empty:
        ctx.note("nac", "unresolved", "nac", "not written: the validator answers HTTP 500 when any of the six NAC lists is empty or missing (empty: {})".format(", ".join(empty)))
        return None
    ctx.note("nac", "mapped", "nac", "dot1x, macAuthProfile, server (address becomes host), serverGroup, aaaProfile, applyPolicies; server keys are secrets")
    return out


def _nac_fix(out: Dict[str, Any], ctx: Optional[Ctx] = None, name_by_if: Optional[Dict[str, Optional[str]]] = None) -> Dict[str, Any]:
    loops = (ctx.data("loopbacks") or {}) if ctx else {}
    for profile in out["aaaProfile"]:
        if not profile.get("da_server"):
            profile["da_server"] = "default"  # required by the validator even when da_enable is false (assumption: the example's value)
    for server in out["server"]:
        server["key"] = "<SECRET:not-captured>"  # Orchestrator returns an empty key; the preconfig requires one
        name = server.get("source_ip_interface")
        if name_by_if and name in name_by_if and name_by_if[name]:
            server["source_ip_interface"] = name_by_if[name]
        elif name in loops:  # the preconfig takes an interface *label*, the appliance reports the interface name
            server["source_ip_interface"] = ctx.label(loops[name]["label"]) or "any"
        elif ctx and name not in (None, "", "any"):
            ctx.readable("ifLabels")
            if name not in ctx.labels.values():
                # an unlabelled interface or one that no longer exists (dangling); the validator rejects anything but a label or "any"
                server["source_ip_interface"] = "any"
        if ctx and name not in (None, "", "any") and server["source_ip_interface"] == "any":
            ctx.note("nac.server[{}]".format(server.get("id")), "unresolved", "nac.server[].source_ip_interface", "{!r} has no interface label (unlabelled or no longer on the appliance); written as 'any'".format(name))
    return out


ENCAP = {"ipsec_ip": "ipsec", "ipsec": "ipsec", "gre": "gre", "gre_ip": "gre", "no_encap": "no_encap", "udp": "ipsec"}


def m_tunnelConfiguration(ctx: Ctx) -> Optional[Dict[str, Any]]:
    source = ctx.data("passthrough-tunnels") or {}
    mine = {k: v for k, v in source.items() if not managed(v)}
    if len(source) > len(mine):
        ctx.note("passthrough-tunnels", "orchestrator-managed", "tunnelConfiguration", "{} passthrough tunnels generated by Orchestrator services (gmsMarked)".format(len(source) - len(mine)))
    if not mine:
        return None
    tunnels = []
    for k, v in sorted(mine.items()):
        try:  # one tunnel with an unexpected value is ledgered and skipped, not the whole section
            encap = ENCAP.get(v["mode"], v["mode"])
            t: Dict[str, Any] = {"tunnelName": v["alias"], "tunnelType": "passthrough", "tunnelEncap": encap, "admin": "Up" if v["adminStatus"] == "up" else "Down", "localIp": v["sourceIpAddress"],
                                 "remoteIp": nul(v["destIpAddress"]), "natMode": v["natMode"], "peerName": nul(v["peerName"]), "enableAutoMaxBandwidth": v["max_bw_auto"], "maxBandwidth": v["max_bw"]}
            if encap == "ipsec":
                id_val = None if v.get("ike_version") == 2 and v.get("id_type") == "address" and v.get("id_str") == v.get("ike_id_local") else nul(v["id_str"])
                t["ikeConfig"] = {"presharedKey": v.get("presharedkey") or "<SECRET:not-captured>", "ikeAuthAlgorithm": v["ike_aalg"], "ikeEncryptAlgorithm": v["ike_ealg"], "diffHellManGroup": int(v["dhgroup"]),
                                  "ikeLifetime": v["ike_lifetime"], "deadPeerDelayTime": v["dpd_delay"], "deadPeerRetryCount": v["dpd_retry"], "identifierType": v["id_type"], "identifierValue": id_val,
                                  "exchangeMode": v["exchange_mode"], "ikeVersion": v["ike_version"], "localIkeIdentifier": nul(v["ike_id_local"]), "remoteIkeIdentifier": nul(v["ike_id_remote"]), "ikePrf": v["ike_prf"]}
                t["ipsecConfig"] = {"ipsecAuthAlgorithm": v["ah"], "ipsecEncryptAlgorithm": "null" if "gmac" in str(v["ah"]) else {"": "auto", None: "auto", "null": "none"}.get(v.get("esp"), v.get("esp")), "enableIpSecArcWindow": 0 if v["ipsecAntiReplayWindow"] == "disable" else int(v["ipsecAntiReplayWindow"]), "ipsecLifetime": v["lifetime"],
                                    "ipsecLifetimeBytes": v["lifebytes"], "secrecyGroup": int(v["pfsgroup"]) if v.get("pfs") else "disable", "ipsecSuiteB": v["ipsec_Suite_b"]}  # null lets the appliance default (PFS on, group 2)
        except (KeyError, TypeError, ValueError) as err:
            ctx.note("passthrough-tunnels[{}]".format(k), "toolkit-error", "tunnelConfiguration", "tunnel {} not written: the mapper could not read it ({}: {}); a toolkit bug to report".format(v.get("alias", k), type(err).__name__, err))
            continue
        tunnels.append(t)
        ctx.unmapped("passthrough-tunnels[{}]".format(k), v, {"id", "alias", "mode", "adminStatus", "sourceIpAddress", "destIpAddress", "natMode", "peerName", "max_bw_auto", "max_bw", "presharedkey", "ike_aalg", "ike_ealg", "dhgroup",
                                                             "ike_lifetime", "dpd_delay", "dpd_retry", "id_type", "id_str", "exchange_mode", "ike_version", "ike_id_local", "ike_id_remote", "ike_prf", "ah", "esp", "ipsecAntiReplayWindow",
                                                             "lifetime", "lifebytes", "pfs", "pfsgroup", "ipsec_Suite_b", "srcNePk", "destNePk", "destTunnelId", "destTunnelAlias", "operStatus", "remoteIdState", "fecStatus",
                                                             "fecRatio", "parallelTunnelId", "local_vrf", "overlayId", "tag", "ipsec_enabled", "max_bw_unshaped"}, "tunnelConfiguration")
    if not tunnels:  # tunnelConfiguration replaces on apply: an empty list would remove the target's tunnels
        return None
    ctx.note("passthrough-tunnels", "mapped", "tunnelConfiguration", "{} user passthrough tunnels; operStatus and ids are runtime; the pre-shared key is a secret column; an empty esp (IPsec encryption) is the stored form of 'auto' and esp 'null' of 'none'; under gmac authentication it is written 'null', which the validator requires".format(len(tunnels)))
    return {"tunnels": tunnels}


def m_virtualTunnelInterface(ctx: Ctx) -> Optional[Dict[str, Any]]:
    source = ctx.data("vtis") or {}
    mine = {k: v for k, v in source.items() if not managed(v)}
    if len(source) > len(mine):
        ctx.note("vtis", "orchestrator-managed", "virtualTunnelInterface", "{} interfaces created by Orchestrator services (gms_marked, third-party cloud tunnels)".format(len(source) - len(mine)))
    if not mine:
        return None
    out = each(ctx, "vtis", "virtualTunnelInterface", sorted(mine.items()), lambda k, v: {
        "interfaceId": k, "ipAddressMask": "{}/{}".format(v["ipaddr"], v["nmask"]), "ipAddressAliasMask": "{}/{}".format(v["ipaddr_alias"], v["nmask_alias"]) if v.get("ipaddr_alias") not in (None, "", "0.0.0.0") else None,
        "adminStatus": ADMIN[bool(v["admin"])], "passthroughTunnel": nul(v["tunnel"]), "interfaceType": v["side"], "interfaceLabel": ctx.label(v["label"]), "interfaceLabelAlias": ctx.label(v.get("label_alias")),
        "zone": ctx.zone(v["vrf_id"], v["zone"]), "role": ctx.role(v.get("role_id", 0)), "segment": ctx.segment(v["vrf_id"]), "autoDistribute": v["auto_distribute"], "behindNat": v["behindNAT"]})
    if not out:
        return None
    ctx.note("vtis", "mapped", "virtualTunnelInterface", "{} user interfaces (no user-defined sample was available: shape verified against the validator only on synthetic data)".format(len(out)))
    return {"vtis": out}


def m_branchNatMapsConfig(ctx: Ctx) -> Optional[Dict[str, Any]]:
    data = ctx.data("branch-nat-maps") or {}
    pools = ctx.data("nat-pools") or {}
    pool_index = {str(k): i for i, k in enumerate(sorted(pools, key=int))}  # natPools is written in this order (m_natPools)
    rules = []
    for map_name, mp in data.items() if isinstance(data, dict) else []:
        if not isinstance(mp, dict):  # names only ({"map1": "map1"}): the map is left with no rules (references/lessons.md)
            continue
        for prio, e in sorted((mp.get("prio") or {}).items(), key=lambda kv: num_key(kv[0])):
            try:
                if managed(e):
                    continue
                m = e.get("match") or {}
                st = e.get("set") or {}
                rule: Dict[str, Any] = {
                    "priorityLevel": int(prio),
                    "segment": ctx.segment(m.get("segment", "0")),
                    "direction": e.get("dir"),
                    "enable": bool(e.get("enable", True)),
                    "comment": nul(e.get("comment")),
                    "interfaceName": m.get("intf", "any"),
                    "protocol": m.get("proto", "any"),
                }
                any_ip = lambda v: "any" if v == "0.0.0.0/0" else v  # the validator rejects the zero address and wants "any"
                if m.get("src_subnet"):
                    rule["sourceIpSubnet"] = any_ip(m["src_subnet"])
                if m.get("dst_subnet"):
                    rule["destinationIpSubnet"] = any_ip(m["dst_subnet"])
                if m.get("dst_port"):
                    rule["destinationPort"] = str(m["dst_port"])
                if str(st.get("trans_src")) in pool_index:  # a NAT pool key, not a subnet: the preconfig refers to pools by list index
                    rule["translateNatPoolID"] = pool_index[str(st["trans_src"])]
                elif st.get("trans_src"):
                    rule["translateSourceIpSubnet"] = st["trans_src"]
                elif "pool_id" in st and st["pool_id"] not in (None, ""):
                    rule["translateNatPoolID"] = int(st["pool_id"])
                if st.get("trans_dst"):
                    rule["translateDestinationIpSubnet"] = st["trans_dst"]
                if st.get("trans_dport"):
                    rule["translateDestinationPort"] = str(st["trans_dport"])
                rules.append(rule)
            except ITEM_ERRORS as err:
                item_failed(ctx, "branch-nat-maps[{}] rule {}".format(map_name, prio), "branchNatMapsConfig", err)
                continue
    names_only = sorted(k for k, v in data.items() if not isinstance(v, dict)) if isinstance(data, dict) else []
    if not rules and names_only:  # owner ruling, docs/decisions/0004: names-only means no rules
        ctx.note("branch-nat-maps", "default-omitted", "branchNatMapsConfig", "no branch NAT rules configured (/nat/maps lists map {} by name only, with no rules)".format(", ".join(names_only)))
        return None
    if not rules and ctx.failed("branchNatMapsConfig"):
        return None
    if not rules:
        ctx.note("branch-nat-maps", "default-omitted", "branchNatMapsConfig", "no branch NAT rules configured in /nat/maps")
        return None
    ctx.note("branch-nat-maps", "mapped", "branchNatMapsConfig", "{} branch NAT rule(s) from /nat/maps".format(len(rules)))
    return {"branchNatRules": rules}


def m_ipAllowList(ctx: Ctx) -> Optional[Dict[str, Any]]:
    src = ctx.data("ip-allow-list") or {}
    items = src.get("ip") or {}
    if not src.get("enable") and not items:
        ctx.note("ip-allow-list", "default-omitted", "ipAllowList", "allow list disabled and empty")
        return None
    if not items:
        return None
    ips = [{"ip": k.split("/")[0], "prefixLength": v["prefixLength"], "comment": nul(v.get("comment")), "protocol": v["protocol"]} for k, v in sorted(items.items())]
    ctx.note("ip-allow-list", "mapped", "ipAllowList", "{} entries from the appliance's allow list (entries applied via preconfig/Orchestrator have gmsMarked=true)".format(len(ips)))
    return {"enable": src["enable"], "ips": ips}


MAPPERS: Dict[str, Callable[[Ctx], Any]] = {
    "ipAllowList": m_ipAllowList,
    "tunnelConfiguration": m_tunnelConfiguration,
    "virtualTunnelInterface": m_virtualTunnelInterface,
    "branchNatMapsConfig": m_branchNatMapsConfig,
    "nac": m_nac,
    "managementIp": m_managementIp,
    "peerPriority": m_peerPriority,
    "appExpressGroups": m_appExpressGroups,
    "thirdPartyServicesAssociation": m_thirdPartyServicesAssociation,
    "multicast": m_multicast,
    "ipSlaRule": m_ipSlaRule,
    "idsIpsConfig": m_idsIpsConfig,
    "flowRedirection": m_flowRedirection,
    "vxlan": m_vxlan,
    "ecLicensing": m_ecLicensing,
    "managementRoutes": m_managementRoutes,
    "localRoutes": m_localRoutes,
    "segmentLocalRoutes": m_segmentLocalRoutes,
    "pppoe": m_pppoe,
    "dhcpRemoteAddressPoolConfig": m_dhcpRemoteAddressPoolConfig,
    "interfaceConfig": m_interfaceConfig,
    "bgpSystemConfig": m_bgpSystemConfig,
    "segmentBgpSystems": m_segmentBgpSystems,
    "vrrp": m_vrrp,
    "natPools": m_natPools,
    "bridgeGroups": m_bridgeGroups,
    "segmentOspfConfig": m_segmentOspfConfig,
    "ospfSystemConfig": m_ospfSystemConfig,
    "loopbackInterface": m_loopbackInterface,
    "linkAggregation": m_linkAggregation,
    "segmentBfdConfigs": m_segmentBfdConfigs,
    "customApplianceTags": m_customApplianceTags,
    "inboundPortForwarding": m_inboundPortForwarding,
    "secureWebServicesConfig": m_secureWebServicesConfig,
}
