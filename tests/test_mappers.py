import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "harnesses"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "toolkit" / "scripts"))
from lab_diff import GuardrailError, check_guardrails, compare_intended_vs_actual  # noqa: E402
from common import parse_yaml  # noqa: E402
from mappers import Ctx, m_bgpSystemConfig, m_branchNatMapsConfig, m_dhcpRemoteAddressPoolConfig, m_flowRedirection, m_ipAllowList, m_multicast, m_nac, m_peerPriority, m_segmentBgpSystems, m_tunnelConfiguration, m_vrrp, m_vxlan, m_managementIp, m_ecLicensing, m_managementRoutes, m_secureWebServicesConfig, passthrough_max_bandwidth  # noqa: E402
from synth import substitute  # noqa: E402
from mappers import m_idsIpsConfig, m_interfaceConfig, m_segmentOspfConfig  # noqa: E402
from suite import load_constraints  # noqa: E402
from translate import HARDEN, QUIET, allowed_paths, build, drop_template_fields, local_firewall_rules, prune, template_fields  # noqa: E402  guard-ok: scripts are imported after the sys.path insert
import copy  # noqa: E402


class FakeCap:
    def __init__(self, data):
        self.run = {"appliance": {"nePk": "9.NE"}}
        self._d = data

    def data(self, ident, prefer="live"):
        return self._d.get(ident)


DEP = {"sysConfig": {"ifLabels": {"lan": [{"id": "4", "name": "Voice"}], "wan": []}, "vrfs": [{"id": "0", "name": "Default"}], "vrfZonesMap": {}, "roles": [{"id": "0", "name": "default"}]},
       "modeIfs": [{"ifName": "lan0", "applianceIPs": [{"vlan": 0, "label": "4"}]}]}


def ctx(data):
    notes = []
    return Ctx(FakeCap(data), notes), notes


class MapperRules(unittest.TestCase):
    def test_peer_priority_uses_weight_not_metric(self):
        c, _ = ctx({"peer-priority": {"peerlist": {"B": {"peer_metric": 0, "peer_weight": 5}, "A": {"peer_metric": 0, "peer_weight": 10}}}})
        self.assertEqual(m_peerPriority(c), {"peerPriorities": [{"peerName": "A", "priority": 10}, {"peerName": "B", "priority": 5}]})

    def test_vrrp_drops_runtime_state(self):
        c, notes = ctx({"vrrp": [{"groupId": 1, "interface": "lan0", "enable": "Up", "vipaddr": "192.0.2.1", "adv_timer": 100, "priority": 101, "tracker": False, "version": 3, "preempt": True,
                                  "auth": "", "desc": "", "pkt_trace": False, "holddown": 10, "mode": "master", "uptime": "1 day", "vmac": "00:00:5e:00:01:01"}]})
        out = m_vrrp(c)
        self.assertNotIn("mode", out["vrrpEntries"][0])
        self.assertNotIn("authenticationString", out["vrrpEntries"][0])
        self.assertFalse(any(n["disposition"] == "unmapped-source-key" for n in notes))

    def test_nac_with_an_empty_list_is_not_written(self):
        src = {"nacEnable": False, "server": {"1": {"self": 1, "address": "192.0.2.5", "authport": 1812, "key": "", "name": "default", "source_ip_interface": "any"}},
               "serverGroup": {"1": {"self": 1, "name": "default", "server": {"1": {"self": 1, "name": "default"}}}}, "aaaProfile": {"1": {"self": 1, "name": "default", "da_server": ""}},
               "dot1x": {"1": {"self": 1, "name": "default"}}, "macAuthProfile": {"1": {"self": 1, "name": "default"}}, "applyPolicies": {"if": {"lan0": {"profile": "none", "auth_type": 0}}}}
        # every interface trusted (no AAA profile): written without a profile, which /validate accepts and "none" it rejects
        self.assertEqual(m_nac(ctx({"nac": src, "deployment": DEP})[0])["applyPolicies"], [{"id": 1, "auth_interface": "Voice", "auth_type": "trusted"}])
        c, notes = ctx({"nac": dict(src, dot1x={}), "deployment": DEP})
        self.assertIsNone(m_nac(c))
        self.assertTrue(any(n["disposition"] == "unresolved" and "dot1x" in n["note"] for n in notes))
        src["applyPolicies"] = {"if": {"lan0": {"profile": "default", "auth_type": 1}}}
        out = m_nac(ctx({"nac": src, "deployment": DEP})[0])
        self.assertEqual(out["server"][0]["host"], "192.0.2.5")
        self.assertEqual(out["server"][0]["key"], "<SECRET:not-captured>")
        self.assertEqual(out["applyPolicies"][0]["auth_interface"], "Voice")
        src["serverGroup"]["1"]["server"] = {"2": {"self": 2, "name": "radius2"}, "10": {"self": 10, "name": "backup"}, "1": {"self": 1, "name": "default"}}
        self.assertEqual(m_nac(ctx({"nac": src, "deployment": DEP})[0])["serverGroup"][0]["server"], "default, radius2, backup")  # /validate rejects "a,b"

    FACTORY_NAC = {"nacEnable": False, "server": {"1": {"self": 1, "address": "0.0.0.1", "authport": 1812, "key": "", "name": "default", "source_ip_interface": "any"}},
                   "serverGroup": {"1": {"self": 1, "name": "default", "server": {"1": {"self": 1, "name": "default"}}}}, "aaaProfile": {"1": {"self": 1, "name": "default", "da_server": ""}},
                   "dot1x": {"1": {"self": 1, "name": "default"}}, "macAuthProfile": {"1": {"self": 1, "name": "default"}}, "applyPolicies": {"if": {"lan0": {"profile": "none", "auth_type": 0}}}}

    def test_disabled_nac_with_only_factory_objects_is_not_written(self):
        for server in ({"address": "0.0.0.1"}, {"address": ""}):
            with self.subTest(server=server):
                src = copy.deepcopy(self.FACTORY_NAC)
                src["server"]["1"].update(server)
                c, notes = ctx({"nac": src, "deployment": DEP})
                self.assertIsNone(m_nac(c))
                self.assertEqual([(n["disposition"], n["note"]) for n in notes if n["target"] == "nac"],
                                 [("default-omitted", "NAC is disabled and holds only its factory-default objects")])

    def test_disabled_nac_with_any_own_object_is_written(self):
        changes = {"enabled": lambda s: s.update(nacEnable=True), "enable unknown": lambda s: s.update(nacEnable=None),
                   "trusted policy with a profile": lambda s: s["applyPolicies"]["if"]["lan0"].update(profile="default"),
                   "policy auth type": lambda s: s["applyPolicies"]["if"]["lan0"].update(auth_type=1), "server address": lambda s: s["server"]["1"].update(address="192.0.2.5"),
                   "server key": lambda s: s["server"]["1"].update(key="<SECRET:nac.server.1.key>"), "interface policy": lambda s: s["applyPolicies"]["if"]["lan0"].update(profile="default", auth_type=1),
                   "own profile": lambda s: s["aaaProfile"]["1"].update(name="GUEST"), "own group": lambda s: s["serverGroup"]["1"].update(name="radius")}
        for what, change in changes.items():
            with self.subTest(what):
                src = copy.deepcopy(self.FACTORY_NAC)
                change(src)
                c, notes = ctx({"nac": src, "deployment": DEP})
                self.assertIsNotNone(m_nac(c))
                self.assertFalse([n for n in notes if n["disposition"] == "default-omitted" and n["target"] == "nac"])

    def test_multicast_drops_stale_pim_entries_and_reads_list_shape(self):
        data = {"deployment": DEP, "multicast-enable": [{"vrf_id": 0, "enable": True}],
                "multicast-config": [{"vrf_id": 0, "rp": "192.0.2.9", "pim": {"lan0": {"dr_priority": 1, "enable": True, "hello_interval": 30, "join_prune_interval": 30},
                                                                                "GHOST": {"dr_priority": 1, "enable": True, "hello_interval": 30, "join_prune_interval": 30}}, "igmp": {}, "filter_name": None}]}
        c, notes = ctx(data)
        out = m_multicast(c)
        self.assertEqual([p["interfaceName"] for p in out[0]["pim"]], ["lan0"])
        self.assertEqual(out[0]["enable"], "true")
        self.assertTrue(any("GHOST" in n["note"] for n in notes))
        self.assertIsNone(m_multicast(ctx({"multicast-config": {"pim0": {}}})[0]))

    def test_managed_tunnels_are_skipped_and_user_tunnel_maps(self):
        user = {"alias": "T1", "mode": "ipsec_ip", "adminStatus": "up", "sourceIpAddress": "192.0.2.1", "destIpAddress": "198.51.100.1", "natMode": "none", "peerName": "", "max_bw_auto": True, "max_bw": 0,
                "presharedkey": "<SECRET:x>", "ike_aalg": "sha1", "ike_ealg": "default", "dhgroup": "14", "ike_lifetime": 360, "dpd_delay": 10, "dpd_retry": 3, "id_type": "address", "id_str": "a", "exchange_mode": "main",
                "ike_version": 2, "ike_id_local": "", "ike_id_remote": "", "ike_prf": "auto", "ah": "sha1", "esp": "", "ipsecAntiReplayWindow": "8192", "lifetime": 360, "lifebytes": 0, "pfs": True, "pfsgroup": "14",
                "ipsec_Suite_b": "none", "gmsMarked": False}
        c, notes = ctx({"passthrough-tunnels": {"a": dict(user), "b": {"gmsMarked": True}}})
        out = m_tunnelConfiguration(c)
        self.assertEqual(len(out["tunnels"]), 1)
        t = out["tunnels"][0]
        self.assertEqual((t["tunnelEncap"], t["ikeConfig"]["diffHellManGroup"], t["ipsecConfig"]["ipsecEncryptAlgorithm"], t["ipsecConfig"]["secrecyGroup"]), ("ipsec", 14, "auto", 14))  # esp "" is how auto is stored
        self.assertEqual(notes[0]["disposition"], "orchestrator-managed")
        off = m_tunnelConfiguration(ctx({"passthrough-tunnels": {"a": dict(user, pfs=False)}})[0])
        self.assertEqual(off["tunnels"][0]["ipsecConfig"]["secrecyGroup"], "disable")
        self.assertEqual(m_tunnelConfiguration(ctx({"passthrough-tunnels": {"a": dict(user, ipsecAntiReplayWindow="disable")}})[0])["tunnels"][0]["ipsecConfig"]["enableIpSecArcWindow"], 0)  # ECOS stores 0 as "disable"
        c, notes = ctx({"passthrough-tunnels": {"a": dict(user, ipsecAntiReplayWindow="odd"), "b": dict(user, alias="T2")}})
        self.assertEqual([t["tunnelName"] for t in m_tunnelConfiguration(c)["tunnels"]], ["T2"])
        self.assertTrue(any(n["disposition"] == "toolkit-error" and "T1" in n["note"] for n in notes))  # a value the mapper cannot read is a toolkit error, not a gap
        self.assertEqual(m_tunnelConfiguration(ctx({"passthrough-tunnels": {"a": dict(user, esp="null")}})[0])["tunnels"][0]["ipsecConfig"]["ipsecEncryptAlgorithm"], "none")
        for esp in ("null", ""):
            gmac = m_tunnelConfiguration(ctx({"passthrough-tunnels": {"a": dict(user, ah="aes128gmac", esp=esp)}})[0])
            self.assertEqual(gmac["tunnels"][0]["ipsecConfig"]["ipsecEncryptAlgorithm"], "null")

    def test_secure_web_services_kept_when_a_value_is_not_default(self):
        url = {"hasURLClassification": False, "incrementalUpdate": False, "queryOnMiss": False, "urlReputation": 1}
        ip = {"hasIPReputation": False, "incrementalUpdate": False}
        src = lambda u: {"secure-web-services": {"secureWebServicesConfig": {"hasSecureWebServicesConfig": False, "urlClassificationConfig": u, "ipReputationConfig": ip}}}
        self.assertIsNone(m_secureWebServicesConfig(ctx(src(url))[0]))
        self.assertEqual(m_secureWebServicesConfig(ctx(src(dict(url, urlReputation=4)))[0])["urlClassificationConfig"]["urlReputation"], 4)

    def test_secure_web_services_flow_process_is_a_boolean(self):
        # Orchestrator 10.0.0 /validate: "Secure Web Services Config - Not valid value: flowProcess." when the key is missing or not a boolean
        url = {"hasURLClassification": False, "incrementalUpdate": False, "queryOnMiss": False, "urlReputation": 4}
        ip = {"hasIPReputation": False, "incrementalUpdate": False}
        src = lambda u, **top: {"secure-web-services": {"secureWebServicesConfig": dict({"hasSecureWebServicesConfig": False, "urlClassificationConfig": u, "ipReputationConfig": ip}, **top)}}
        c, notes = ctx(src(url))  # ECOS before 10.0: no flowProcess in the read
        self.assertIs(m_secureWebServicesConfig(c)["urlClassificationConfig"]["flowProcess"], True)
        self.assertTrue(any(n["disposition"] == "mapped" and n["target"].endswith(".flowProcess") and "default" in n["note"] for n in notes))
        c, notes = ctx(src(dict(url, flowProcess=None)))  # what Orchestrator 10.0.0.40724 returns for an ECOS 9.7.2 appliance (lab, 2026-10-31)
        self.assertIs(m_secureWebServicesConfig(c)["urlClassificationConfig"]["flowProcess"], True)
        self.assertTrue(any(n["target"].endswith(".flowProcess") for n in notes))
        self.assertIs(m_secureWebServicesConfig(ctx(src(dict(url, flowProcess=False)))[0])["urlClassificationConfig"]["flowProcess"], False)
        self.assertIs(m_secureWebServicesConfig(ctx(src(dict(url, flowProcess="false")))[0])["urlClassificationConfig"]["flowProcess"], False)
        self.assertIs(m_secureWebServicesConfig(ctx(src(dict(url, flowProcess=None)))[0])["urlClassificationConfig"]["flowProcess"], True)
        self.assertIs(m_secureWebServicesConfig(ctx(src(url, flowProcess=False))[0])["urlClassificationConfig"]["flowProcess"], False)  # key next to the wrappers
        c, notes = ctx(src(dict(url, flowProcess="all")))
        self.assertIs(m_secureWebServicesConfig(c)["urlClassificationConfig"]["flowProcess"], True)
        self.assertTrue(any(n["disposition"] == "not-readable" and "'all'" in n["note"] for n in notes))
        # an all-default section of a 10.0 appliance (flowProcess true in the read) is still omitted
        default = dict(url, urlReputation=1, flowProcess=True)
        c, notes = ctx(src(default))
        self.assertIsNone(m_secureWebServicesConfig(c))
        self.assertEqual([n["disposition"] for n in notes], ["default-omitted"])
        c, notes = ctx(src(dict(default, flowProcess=None)))  # all default with a null flowProcess: omitted, no flowProcess line (the section is not written)
        self.assertIsNone(m_secureWebServicesConfig(c))
        self.assertEqual([n["disposition"] for n in notes], ["default-omitted"])
        self.assertIs(m_secureWebServicesConfig(ctx(src(dict(default, flowProcess=False)))[0])["urlClassificationConfig"]["flowProcess"], False)  # first-request only is a setting
        # the written section always carries the key; prune() drops it for a 9.x target
        written = m_secureWebServicesConfig(ctx(src(url))[0])
        ledger = []
        pruned = prune({"secureWebServicesConfig": written}, allowed_paths("9.7.1.42046"), ledger)
        self.assertNotIn("flowProcess", pruned["secureWebServicesConfig"]["urlClassificationConfig"])
        self.assertIn("flowProcess", prune({"secureWebServicesConfig": written}, allowed_paths("10.0.0.40516"), [])["secureWebServicesConfig"]["urlClassificationConfig"])

    def test_cli_sections(self):
        self.assertEqual(passthrough_max_bandwidth(["hostname x", "interface pass-through max-bandwidth 50000"]), 50000)
        self.assertIsNone(passthrough_max_bandwidth(["hostname x"]))
        backup = {"fileName": "b", "backupTime": "1", "runningConfig": "ip mgmt-ip 192.0.2.7\nsystem eclicense boost bandwidth 50000\nsystem eclicense boost enable\n"}
        self.assertEqual(m_managementIp(ctx({"running-config": backup})[0]), {"ipAddress": "192.0.2.7"})
        self.assertEqual(m_ecLicensing(ctx({"running-config": backup})[0]), {"useDefaultAccount": True, "boost": 50000})
        self.assertIsNone(m_managementIp(ctx({"running-config": {"runningConfig": "hostname x"}})[0]))
        cfg = {"runningConfig": "ip default-gateway 192.0.2.1 mgmt0 1\nip route 203.0.113.0 /24 192.0.2.253 mgmt0 10 0.0.0.0\nip route 203.0.113.0 /24 192.0.2.253 mgmt0 10 0.0.0.0\nip route 198.51.100.0 /24 192.0.2.9 lan0 1\n"}
        self.assertEqual(m_managementRoutes(ctx({"running-config": cfg})[0])["routes"],
                         [{"routeIpSubnet": "0.0.0.0/0", "nextHop": "192.0.2.1", "interfaceName": "mgmt0", "metric": 1, "sourceIp": None},
                          {"routeIpSubnet": "203.0.113.0/24", "nextHop": "192.0.2.253", "interfaceName": "mgmt0", "metric": 10, "sourceIp": "0.0.0.0"}])


class Substitution(unittest.TestCase):
    INV = {"groups": ["G"], "overlays": ["O1", "O2"], "templateGroups": ["T"], "lan": ["Voice", "Data"], "wan": ["MPLS1"], "segments": ["Default", "S1"], "zones": ["Default", "Z1"]}

    def test_names_map_one_to_one_by_kind_and_values_stay(self):
        doc = {"applianceInfo": {"hostname": "h", "group": "X", "region": "R"}, "templateGroups": {"groups": ["a", "b"]}, "businessIntentOverlays": {"overlays": ["a", "b", "c"]},
               "deploymentInfo": {"deploymentInterfaces": [{"interfaceName": "lan0", "interfaceType": "lan", "interfaceLabel": "L1", "segment": "Corp", "zone": "Z", "role": "Employee", "ipAddressMask": "192.0.2.1/24"},
                                                         {"interfaceName": "lan1", "interfaceType": "lan", "interfaceLabel": "L2", "segment": "Default"},
                                                         {"interfaceName": "wan0", "interfaceType": "wan", "interfaceLabel": "W1"}]}, "appExpressGroups": ["g"]}
        notes = []
        out = substitute(doc, self.INV, notes)
        i = out["deploymentInfo"]["deploymentInterfaces"]
        self.assertEqual([x["interfaceLabel"] for x in i], ["Voice", "Data", "MPLS1"])
        self.assertEqual((i[0]["segment"], i[1]["segment"], i[0]["role"], i[0]["ipAddressMask"]), ("S1", "Default", "default", "192.0.2.1/24"))
        self.assertIsNone(out["applianceInfo"]["region"])
        self.assertNotIn("appExpressGroups", out)
        self.assertTrue(notes)
        self.assertEqual(doc["applianceInfo"]["group"], "X")  # input untouched


class Release(unittest.TestCase):
    def test_prune_keeps_only_allowed_paths_and_ledgers_each_drop_once(self):
        ledger = []
        out = prune({"a": {"keep": 1, "extra": 2}, "l": [{"extra": 1, "x": 2}, {"extra": 3}]}, {"a", "a.keep", "l", "l.x"}, ledger)
        self.assertEqual(out, {"a": {"keep": 1}, "l": [{"x": 2}, {}]})
        self.assertEqual([(e["target"], e["disposition"]) for e in ledger], [("a.extra", "outside-preconfig"), ("l.extra", "outside-preconfig")])

    def test_allowed_paths_follow_the_target_template_plus_known_omissions(self):
        allowed = allowed_paths("9.7.1.42046")
        self.assertIn("nac.aaaProfile.dot1x_server_group", allowed)
        self.assertIn("deploymentInfo.deploymentInterfaces.addressingMode", allowed)  # /validate accepts it; the template does not show it
        self.assertNotIn("nac.aaaProfile.dot1x_acct_server_group", allowed)
        self.assertNotIn("tunnelConfiguration.tunnels.ipsecConfig.ikePqcgroup", allowed)  # 10.0 only


class Ecos95(unittest.TestCase):
    """ECOS 9.5.x returns keys later releases dropped and leaves out keys they added (lab corpus, 2026-10-27)."""

    def test_nac_accounting_server_groups_are_not_written(self):
        aaa = {"self": 1, "name": "default", "da_enable": False, "da_server": "default", "dot1x_acct_server_group": "default", "dot1x_default_role": "default", "dot1x_profile": "default",
               "dot1x_server_group": "default", "mac_acct_server_group": "default", "mac_default_role": "default", "mac_profile": "default", "mac_server_group": "default", "stats_timeout": 10}
        src = {"nacEnable": False, "server": {"1": {"self": 1, "address": "192.0.2.5", "authport": 1812, "key": "", "name": "default", "source_ip_interface": "any"}},
               "serverGroup": {"1": {"self": 1, "name": "default", "server": {"1": {"self": 1, "name": "default"}}}}, "aaaProfile": {"1": aaa},
               "dot1x": {"1": {"self": 1, "name": "default"}}, "macAuthProfile": {"1": {"self": 1, "name": "default"}}, "applyPolicies": {"if": {"lan0": {"profile": "default", "auth_type": 1}}}}
        ledger = []
        out = prune({"nac": m_nac(ctx({"nac": src, "deployment": DEP})[0])}, allowed_paths("9.7.1.42046"), ledger)
        self.assertNotIn("dot1x_acct_server_group", out["nac"]["aaaProfile"][0])
        self.assertNotIn("mac_acct_server_group", out["nac"]["aaaProfile"][0])
        self.assertEqual(out["nac"]["aaaProfile"][0]["dot1x_server_group"], "default")
        self.assertEqual(sorted(e["target"] for e in ledger), ["nac.aaaProfile.dot1x_acct_server_group", "nac.aaaProfile.mac_acct_server_group"])

    def test_ip_sla_rule_without_route_label(self):
        from mappers import m_ipSlaRule
        op = {"type": "ip-monitor", "ip-monitor-ip": "192.0.2.98", "tunnel-name": "to_peer_DefaultOverlay", "src-port-name": "lo20000"}
        c, notes = ctx({"deployment": DEP, "ipsla-managers": {"MGR_1": {"enable": True, "interval": "1", "comment": "", "upAction": "def-alarm", "downAction": "alarm", "operation": {"OPR_1": op}}}})
        rule = m_ipSlaRule(c)["ruleEntries"][0]
        self.assertIsNone(rule["routeLabel"])
        self.assertEqual(rule["ipslaMonitor"]["tunnelName"], "to_peer_DefaultOverlay")

    def test_vrrp_without_tracker(self):
        c, _ = ctx({"vrrp": [{"groupId": 100, "interface": "lan1", "enable": "Up", "vipaddr": "192.0.2.1", "adv_timer": 1, "priority": 128, "version": 2, "preempt": True,
                              "auth": "", "desc": "vrrp ipv4", "pkt_trace": False, "holddown": 60}]})
        self.assertFalse(m_vrrp(c)["vrrpEntries"][0]["tracker"])  # no tracker on 9.5.x is the template default, false

    def test_ha_group_without_ipv6_pool_gets_orchestrator_default(self):
        dep = copy.deepcopy(DEP)
        dep["sysConfig"]["haIf"] = "lan1"
        dep["sysConfig"]["ifLabels"]["wan"] = [{"id": "1", "name": "INET"}]
        wan = {"vlan": 0, "label": "1", "wanSide": True, "vrf": 0, "zone": 0, "harden": 1, "behindNAT": "none", "maxBW": {"outbound": 50000, "inbound": 50000}, "version": 4, "ip": "198.51.100.10", "mask": 24, "wanNexthop": "198.51.100.1"}
        dep["modeIfs"] = [{"ifName": "wan0", "applianceIPs": [wan]}, {"ifName": "lan1", "applianceIPs": [dict(wan, vlan=4000)]}]
        ha = {"g1": {"subnet": "169.254.1.0/24", "mask": 30, "v6HaSubnet": None, "v6HaMask": 0, "vlanStart": 4000, "appliances": [{"nePk": "9.NE"}, {"nePk": "8.NE"}]}}
        cap = FakeCap({"appliance": {"hostName": "h1", "groupId": "1.Network", "site": "S1", "networkRole": "0"}, "deployment": dep, "ha-groups": ha})
        cap.folder = "fake"
        ha_cfg = build(cap, [])["deploymentInfo"]["haConfig"]
        self.assertEqual((ha_cfg["hav6IpPool"], ha_cfg["hav6SubnetMask"]), ("fd00::a9fe:0000/112", 126))  # /validate rejects mask 0

    def test_bonded_interface_without_speed_is_default_not_unresolved(self):
        c, notes = ctx({"interface-state": {"ifInfo": [{"ifname": "blan0", "ifSpeed": "", "ifDuplex": "", "admin": True}]}})
        self.assertIsNone(m_interfaceConfig(c))
        self.assertFalse(any(n["disposition"] == "unresolved" for n in notes))


class ApplyGuardrailAndDiff(unittest.TestCase):
    def test_guardrails_enforce_vlab_wan0_dhcp_100m_and_no_mgmt_ip(self):
        valid = {"deploymentInfo": {"deploymentInterfaces": [{"interfaceName": "wan0.4000", "addressingMode": "dhcpv4", "inboundMaxBandwidth": 100000, "outboundMaxBandwidth": 100000}]}}
        check_guardrails("vlab", valid)
        with self.assertRaises(GuardrailError):
            check_guardrails("prod", valid)
        with self.assertRaises(GuardrailError):
            check_guardrails("vlab", {"managementIp": {"ipAddress": "192.0.2.1"}})
        with self.assertRaises(GuardrailError):
            check_guardrails("vlab", {"deploymentInfo": {"deploymentInterfaces": [{"interfaceName": "wan0.4000", "addressingMode": "static", "inboundMaxBandwidth": 100000, "outboundMaxBandwidth": 100000}]}})
        with self.assertRaises(GuardrailError):
            check_guardrails("vlab", {"deploymentInfo": {"deploymentInterfaces": [{"interfaceName": "wan0.4000", "addressingMode": "dhcpv4", "inboundMaxBandwidth": 50000, "outboundMaxBandwidth": 100000}]}})

    def test_compare_intended_vs_actual(self):
        intended = {"applianceInfo": {"hostname": "h1", "region": None}, "bgpSystemConfig": {"asn": 65001, "neighbors": [{"password": "secret"}]}}
        actual = {"applianceInfo": {"hostname": "h1"}, "bgpSystemConfig": {"asn": 65002, "neighbors": [{"password": "<SECRET:$.x>"}]}}
        diff = compare_intended_vs_actual(intended, actual)
        self.assertEqual(diff["mismatch_count"], 1)
        self.assertEqual(diff["mismatches"][0]["path"], "bgpSystemConfig.asn")
        self.assertEqual(diff["missing_count"], 0)

    def test_compare_reads_single_segment_intent_from_segment_default(self):
        intended = {"bgpSystemConfig": {"asn": 65001, "enable": True}}
        actual = {"segmentBgpSystems": [{"segment": "corp", "asn": 65009}, {"segment": "Default", "asn": 65001, "enable": True}]}
        diff = compare_intended_vs_actual(intended, actual)
        self.assertEqual((diff["matched_count"], diff["mismatch_count"], diff["missing_count"]), (2, 0, 0))

    def test_compare_aligns_reordered_lists_by_identity_key(self):
        intended = {"deploymentInfo": {"deploymentInterfaces": [{"interfaceName": "lan0", "zone": "a"}, {"interfaceName": "lan0.90", "zone": "b"},
                                                                {"interfaceName": "wan1", "zone": "c"}]}}
        actual = {"deploymentInfo": {"deploymentInterfaces": [{"interfaceName": "wan1", "zone": "c"}, {"interfaceName": "lan0", "zone": "a"},
                                                              {"interfaceName": "wan0.4000", "zone": "d"}]}}
        diff = compare_intended_vs_actual(intended, actual)
        self.assertEqual(diff["mismatch_count"], 0)
        self.assertEqual([m["path"] for m in diff["missing_in_actual"]], ["deploymentInfo.deploymentInterfaces[1].interfaceName", "deploymentInfo.deploymentInterfaces[1].zone"])
        self.assertEqual([e["actual"] for e in diff["extra_in_same_sections"]], ["wan0.4000", "d"])

    def test_vlab_discovered_fixes(self):
        self.assertEqual(HARDEN, {0: "All", 1: "harden", 2: "stateful", 3: "statefulSNAT"})
        # managementIp omitted when mgmt0 is DHCP
        backup = {"fileName": "b", "backupTime": "1", "runningConfig": "ip mgmt-ip 192.0.2.187\n"}
        self.assertIsNone(m_managementIp(ctx({"running-config": backup, "deployment": {"mgmtIfData": {"mgmt0": {"dhcp": True}}}})[0]))
        # ipAllowList includes gmsMarked entries pushed by Orchestrator
        allow = m_ipAllowList(ctx({"ip-allow-list": {"enable": True, "ip": {"192.0.2.0/24": {"prefixLength": 24, "comment": "lab", "protocol": ["https", "ssh"], "gmsMarked": True}}}})[0])
        self.assertEqual(allow["ips"][0]["ip"], "192.0.2.0")
        # branchNatMapsConfig reads /nat/maps
        nat = m_branchNatMapsConfig(ctx({"deployment": DEP, "branch-nat-maps": {"map1": {"prio": {"10": {"dir": "outbound", "enable": True, "comment": "c",
            "match": {"intf": "any", "segment": "0", "proto": "tcp", "src_subnet": "192.0.2.0/24", "dst_subnet": "10.0.0.0/16", "dst_port": "1-10"},
            "set": {"trans_src": "198.51.100.0/24", "trans_dst": "10.0.0.0/16", "trans_dport": "11-20"}}}}}})[0])
        self.assertEqual(nat["branchNatRules"][0]["translateSourceIpSubnet"], "198.51.100.0/24")
        # Multi-segment BGP omits bgpSystemConfig and puts Default + non-Default inside segmentBgpSystems
        dep2 = {"sysConfig": {"ifLabels": {"lan": [], "wan": []}, "vrfs": [{"id": "0", "name": "Default"}, {"id": "1", "name": "corp"}], "vrfZonesMap": {}, "roles": []}}
        bgp_all = {"0": {"enable": True, "asn": 65001, "rtr_id": "192.0.2.1", "graceful_restart_en": True, "max_restart_time": 120, "stale_path_time": 150, "remote_as_path_advertise": True},
                   "1": {"enable": True, "asn": 65101, "rtr_id": "203.0.113.1", "graceful_restart_en": True, "max_restart_time": 120, "stale_path_time": 150, "remote_as_path_advertise": True}}
        data = {"deployment": dep2, "bgp-system": bgp_all["0"], "bgp-neighbors": {}, "bgp-system-all-vrfs": bgp_all, "bgp-neighbors-all-vrfs": {"0": {}, "1": {}}}
        self.assertIsNone(m_bgpSystemConfig(ctx(data)[0]))
        segs = m_segmentBgpSystems(ctx(data)[0])
        self.assertEqual([s["segment"] for s in segs], ["Default", "corp"])

    def test_round2_97_and_edge_case_fixes(self):
        # Leading-zero numeric string (NJ ZIP 08034) does not crash octal parser
        self.assertEqual(parse_yaml("zipCode: 08034\ncount: 10\n"), {"zipCode": "08034", "count": 10})
        # dhcpRemoteAddressPoolConfig skips local interface DHCP pools and keeps only remote pools
        pools = [{"interface": "lan0", "subnet": "10.0.0.0/24", "scopeName": "lan0-10", "ipRange": [], "gatewayIp": "10.0.0.1", "dnsServers": [], "ntpServers": [], "netbiosNameServers": [], "netbiosNodeType": "B", "maxLeaseTime": 600, "defaultLeaseTime": 60},
                 {"interface": None, "subnet": "192.168.8.0/24", "scopeName": "GUEST", "ipRange": [], "gatewayIp": "192.168.8.1", "dnsServers": [], "ntpServers": [], "netbiosNameServers": [], "netbiosNodeType": "B", "maxLeaseTime": 600, "defaultLeaseTime": 60}]
        self.assertEqual(m_dhcpRemoteAddressPoolConfig(ctx({"dhcp-remote-subnets": pools})[0])["dhcpAddressMask"], "192.168.8.0/24")
        # multicast igmpEnable reads seg['igmp'][k]['enable']
        mc = m_multicast(ctx({"deployment": DEP, "multicast-enable": [{"vrf_id": 0, "enable": True}],
                              "multicast-config": [{"vrf_id": 0, "rp": "192.0.2.9", "pim": {"lan0": {"dr_priority": 1, "enable": True, "hello_interval": 30, "join_prune_interval": 30}},
                                                    "igmp": {"lan0": {"enable": False}}, "filter_name": None}]})[0])
        self.assertFalse(mc[0]["pim"][0]["igmpEnable"])
        # vxlan and flowRedirection read live JSON endpoints
        vx = m_vxlan(ctx({"deployment": DEP, "vxlan": {"port": 4789, "vtepIf": "lo1"}, "vxlan-vni-map": {"0": {"vni": 1001, "zoneId": 0, "role": 0}}})[0])
        self.assertEqual((vx["vtepSrcInterface"], vx["vniVrfMaps"][0]["vni"]), ("lo1", 1001))
        fr = m_flowRedirection(ctx({"cluster-state": {"S1": {"siteApplianceInterfaceIps": {"9.NE": {"state": {"flow_redir": True, "wait_time": 10, "interface": "wan1", "peerIPStatusList": [{"peerIP": "192.0.2.1"}]}}}}}})[0])
        self.assertEqual((fr["interfaceName"], fr["peers"][0]["peerIp"]), ("wan1", "192.0.2.1"))
        # running-config fallback: no wait-time line means the ECOS default 50, a line overrides it
        cfg = "cluster interface wan1\ncluster peer 192.0.2.1\nflow-redirection enable"
        self.assertEqual(m_flowRedirection(ctx({"running-config": {"runningConfig": cfg}})[0])["waitTime"], 50)
        self.assertEqual(m_flowRedirection(ctx({"running-config": {"runningConfig": cfg + "\nflow-redirection wait-time 20"}})[0])["waitTime"], 20)


class AuditRegressions(unittest.TestCase):
    """Payload shapes from older/newer ECOS releases and lab runs that crashed a mapper, aborted translate, or wrote a wrong value."""

    def _build(self, ips, ifname="lan0", ledger=None, **extra):
        dep = copy.deepcopy(DEP)
        dep["sysConfig"]["ifLabels"]["wan"] = [{"id": "1", "name": "INET"}]
        dep["modeIfs"] = [{"ifName": ifname, "applianceIPs": ips}]
        data = dict({"appliance": {"hostName": "h1", "groupId": "1.Network", "site": "S1", "networkRole": "0"}, "deployment": dep}, **extra)
        cap = FakeCap(data)
        cap.folder = "fake"
        return build(cap, [] if ledger is None else ledger)

    def test_local_firewall_rules_are_ledgered_not_written(self):
        rule = {"gms_marked": False, "match": {"acl": "a"}, "set": {"action": "allow"}}
        maps = {"map1": {"12_13": {"prio": {"1000": rule, "1010": rule, "65535": rule, "1020": dict(rule, gms_marked=True)}}, "13_12": {"prio": {"1500": rule}}}}
        text = local_firewall_rules(FakeCap({"security-maps": maps}))
        self.assertTrue(text.startswith("3 firewall rule(s) and 1 zone-pair default rule(s)"))
        self.assertIsNone(local_firewall_rules(FakeCap({"security-maps": {"map1": {"12_13": {"prio": {"1020": dict(rule, gms_marked=True)}}}}})))
        self.assertIsNone(local_firewall_rules(FakeCap({})))
        ledger = []
        wan = {"vlan": 0, "label": "1", "wanSide": True, "vrf": 0, "zone": 0, "harden": 1, "behindNAT": "none", "maxBW": {"outbound": 50000}, "intf_mode": "static_slaac",
               "version": 4, "ip": "198.51.100.10", "mask": 24, "wanNexthop": "198.51.100.1"}
        doc = self._build([wan], "wan0", ledger, **{"security-maps": maps})
        self.assertEqual([e["disposition"] for e in ledger if e["item"] == "security-maps"], ["unresolved"])
        self.assertFalse(any("ecurity" in k or "irewall" in k for k in doc))

    def test_admin_distance_and_sse_interfaces_are_ledgered_not_dropped(self):
        distance = {"ebgp": 16, "ibgp": 200, "ospf": 110}
        sse = {"admin": True, "interface": "veth20000", "ip_addr": "192.0.2.6", "mask": 31}
        ledger = []
        self._build([], ledger=ledger, **{"admin-distance": distance, "sse-interfaces": sse})
        got = {e["item"]: e for e in ledger if e["item"] in ("admin-distance", "sse-interfaces")}
        self.assertEqual(got["admin-distance"]["disposition"], "unresolved")
        self.assertIn("ebgp 16", got["admin-distance"]["note"])
        self.assertEqual(got["sse-interfaces"]["disposition"], "orchestrator-managed")
        self.assertIn("veth20000", got["sse-interfaces"]["note"])
        ledger = []
        groups = [{"name": "G1", "selectedTemplateNames": ["adminDistance"], "templates": []}]
        self._build([], ledger=ledger, **{"admin-distance": distance, "template-association": {"templateIds": ["G1"]}, "template-groups": groups})
        self.assertEqual([e["disposition"] for e in ledger if e["item"] == "admin-distance"], ["template-group"])

    def test_template_fields_owns_only_fields_a_selected_associated_template_sets(self):
        routes = {"name": "routes", "value": {"ecmp_en": True, "auto_subnet": {"vrf": {"0": {"add_local_lan": True, "add_local_metric": 50, "local_communities": "", "add_local_communities": "none"},
                                                                                   "82": {"local_asn_filter": "true"}}}}}
        vrrp = {"name": "vrrp", "value": {"admin": "Up", "advTimer": "", "priority": "", "preempt": False, "auth": "x"}}
        bgp = {"name": "bgp", "value": {"vrf": {"0": {"graceful_restart_en": "none", "max_restart_time": 120, "route_target_template": {"import": "65000:1", "export": ""}}}}}
        groups = [{"name": "G1", "selectedTemplateNames": ["routes", "vrrp"], "templates": [routes, vrrp, bgp]},
                  {"name": "G2", "selectedTemplateNames": ["bgp"], "templates": [bgp]},
                  {"name": "G3", "selectedTemplateNames": ["vrrp"], "templates": [dict(vrrp, value={"priority": 200})]}]
        owned = template_fields(FakeCap({"template-association": {"templateIds": ["G1", "G2"]}, "template-groups": groups}))
        self.assertEqual(owned["routes"], {"0": {"advertiseLocalLanSubnets", "localMetric"}, "82": {"filterRoutesWithLocalASN"}})
        self.assertEqual(owned["vrrp"], {None: {"admin", "preemption", "authenticationString"}})
        self.assertEqual(owned["bgp"], {"0": {"maxRestartTime", "importRouteTarget"}})

    def test_drop_template_fields_keeps_what_no_template_sets(self):
        out = {"vrrp": {"vrrpEntries": [{"groupId": 1, "interfaceName": "lan0", "virtualIpAddress": "192.0.2.1", "admin": "up", "priority": 110}]},
               "localRoutes": {"advertiseLocalLanSubnets": True, "localMetric": 50, "routes": []},
               "segmentBgpSystems": [{"segment": "Default", "asn": 65001, "maxRestartTime": 120, "neighbors": []}, {"segment": "Guest", "asn": 65001, "maxRestartTime": 90, "neighbors": []}]}
        notes = []
        owned = {"vrrp": {None: {"admin"}}, "routes": {"0": {"advertiseLocalLanSubnets", "localMetric"}}, "bgp": {"0": {"maxRestartTime"}}}
        drop_template_fields(out, owned, {"0": "Default", "82": "Guest"}, lambda *a: notes.append(a))
        self.assertEqual(out["vrrp"]["vrrpEntries"][0], {"groupId": 1, "interfaceName": "lan0", "virtualIpAddress": "192.0.2.1", "priority": 110})
        self.assertNotIn("localRoutes", out)
        self.assertNotIn("maxRestartTime", out["segmentBgpSystems"][0])
        self.assertEqual(out["segmentBgpSystems"][1]["maxRestartTime"], 90)
        self.assertIn("assumption", next(n[3] for n in notes if n[:2] == ("template bgp", "mapped")))  # written, but the owner confirms it

    def test_vrrp_template_no_longer_drops_vrrp_groups(self):
        vrrp_src = [{"groupId": 1, "interface": "lan0", "enable": True, "vipaddr": "192.0.2.1", "adv_timer": 1, "priority": 110, "tracker": "", "version": 2,
                     "preempt": True, "auth": "", "desc": "", "pkt_trace": False, "holddown": 10}]
        groups = [{"name": "G1", "selectedTemplateNames": ["vrrp"], "templates": [{"name": "vrrp", "value": {"admin": "Up", "advTimer": "", "priority": "", "preempt": False}}]}]
        wan = {"vlan": 0, "label": "1", "wanSide": True, "vrf": 0, "zone": 0, "harden": 1, "behindNAT": "none", "maxBW": {"outbound": 50000}, "intf_mode": "static_slaac",
               "version": 4, "ip": "198.51.100.10", "mask": 24, "wanNexthop": "198.51.100.1"}
        doc = self._build([wan], "wan0", **{"vrrp": vrrp_src, "template-association": {"templateIds": ["G1"]}, "template-groups": groups})
        entry = doc["vrrp"]["vrrpEntries"][0]
        self.assertEqual((entry["groupId"], entry["priority"]), (1, 110))
        self.assertNotIn("admin", entry)
        self.assertNotIn("preemption", entry)

    def _two_lans(self, **extra):
        dep = copy.deepcopy(DEP)
        dep["sysConfig"]["ifLabels"]["lan"].append({"id": "5", "name": "Data"})
        dep["sysConfig"]["vrfs"].append({"id": "1", "name": "Guest"})
        lan = {"vlan": 0, "wanSide": False, "vrf": 0, "zone": 0, "mask": 24}
        dep["modeIfs"] = [{"ifName": "lan0", "applianceIPs": [dict(lan, label="4", ip="192.0.2.1")]}, {"ifName": "lan1", "applianceIPs": [dict(lan, label="5", ip="198.51.100.1")]}]
        ledger = []
        return self._build([], ledger=ledger, deployment=dep, **{"template-association": {"templateIds": ["G1"]}, **extra}), ledger

    def test_nac_merge_template_ledgers_the_local_objects_without_writing_nac(self):
        def obj(name):
            return {"self": 1, "name": name}
        nac = {"nacEnable": True, "server": {"1": {"address": "192.0.2.5", "authport": 1812, "key": "", "name": "default", "source_ip_interface": "any"}},
               "serverGroup": {"1": {"name": "default", "server": "default"}}, "aaaProfile": {"1": dict(obj("default"), da_server="default"), "2": dict(obj("corp"), da_server="default")},
               "dot1x": {"1": obj("default")}, "macAuthProfile": {"1": obj("default")},
               "applyPolicies": {"if": {"lan0": {"profile": "default", "auth_type": 1}, "lan1": {"profile": "corp", "auth_type": 2}}}}
        tpl = {"merge": True, "nacEnable": True, "server": {"1": {"name": "default"}}, "serverGroup": {"1": {"name": "default"}}, "aaaProfile": {"1": {"name": "default"}},
               "dot1x": {"1": {"name": "default"}}, "macAuthProfile": {"1": {"name": "default"}}, "applyPolicies": {"if": {"Voice": {"auth_type": 1, "profile": "default", "self": "Voice"}}}}
        groups = [{"name": "G1", "selectedTemplateNames": ["nac"], "templates": [{"name": "nac", "value": tpl}]}]
        doc, ledger = self._two_lans(nac=nac, **{"template-groups": groups})
        # /validate answers HTTP 500 unless all six lists are non-empty, and the other lists hold only the template's objects: nothing is written
        self.assertNotIn("nac", doc)
        local = [e for e in ledger if e["item"] == "nac (local objects under a merge template)"]
        self.assertEqual([e["disposition"] for e in local], ["outside-preconfig"])
        self.assertIn("aaaProfile corp, applyPolicies Data", local[0]["note"])
        self.assertIn("/validate", local[0]["note"])
        self.assertNotIn("aaaProfile default", local[0]["note"])  # the template's own objects are not listed as local
        self.assertEqual([e for e in ledger if e["target"].startswith("nac") and e["disposition"] == "mapped"], [])  # nothing claims a NAC section
        owned = next(e["note"] for e in ledger if e["item"] == "template nac" and e["disposition"] == "template-group")
        self.assertIn("merge", owned)
        self.assertIn("the section is not written", owned)
        # a trusted policy is the appliance default, not a local setting to redo by hand
        trusted = dict(nac, applyPolicies={"if": {"lan0": {"profile": "default", "auth_type": 1}, "lan1": {"profile": "none", "auth_type": 0}}})
        doc, ledger = self._two_lans(nac=trusted, **{"template-groups": groups})
        self.assertNotIn("applyPolicies", next(e["note"] for e in ledger if e["item"] == "nac (local objects under a merge template)"))
        # the NAC read failed: what is local is unknown, so it is not-readable, never silently "nothing local"
        doc, ledger = self._two_lans(**{"template-groups": groups})
        self.assertEqual([e["disposition"] for e in ledger if e["item"].startswith("nac (local")], ["not-readable"])
        # without merge the template replaces the appliance's NAC: the section stays out, as before
        groups[0]["templates"][0]["value"] = dict(tpl, merge=False)
        doc, ledger = self._two_lans(nac=nac, **{"template-groups": groups})
        self.assertNotIn("nac", doc)
        self.assertIn("the section is not written", next(e["note"] for e in ledger if e["item"] == "template nac"))

    def test_bgp_route_targets_with_apply_status_none_are_not_template_owned(self):
        rt = {"import": "0:0", "export": "0:0"}
        bgp = {"name": "bgp", "value": {"vrf": {"0": {"max_restart_time": 120, "route_target_template": dict(rt, applyStatus="none")},
                                               "1": {"route_target_template": dict(rt, applyStatus="NONE")},
                                               "2": {"route_target_template": rt}}}}  # no applyStatus: owned, as before
        groups = [{"name": "G1", "selectedTemplateNames": ["bgp"], "templates": [bgp]}]
        owned = template_fields(FakeCap({"template-association": {"templateIds": ["G1"]}, "template-groups": groups}))
        self.assertEqual(owned["bgp"], {"0": {"maxRestartTime"}, "1": set(), "2": {"importRouteTarget", "exportRouteTarget"}})

    def test_vxlan_template_without_a_vtep_leaves_the_vtep_to_the_appliance(self):
        live = {"vxlan": {"port": 4789, "vtepIf": "lo1"}, "vxlan-vni-map": {"0": {"vni": 1001}, "1": {"vni": 1002}}}
        def run(tpl):
            groups = [{"name": "G1", "selectedTemplateNames": ["vxlan"], "templates": [{"name": "vxlan", "value": tpl}]}]
            return self._two_lans(**live, **{"template-groups": groups})
        doc, ledger = run({"port": "4789", "vrfId": {"1": {"role": "0", "vni": 5000, "zoneId": 0}}, "vtepIf": "none"})
        got = doc.get("vxlan") or {}
        self.assertEqual(got.get("vtepSrcInterface"), "lo1")
        self.assertEqual(got.get("destinationUdpPort"), 4789)  # the template sets it too, but /validate requires it
        port = [e for e in ledger if e["item"] == "vxlan destinationUdpPort"]
        self.assertEqual([e["disposition"] for e in port], ["mapped"])
        self.assertIn("requires", port[0]["note"])
        self.assertEqual([m["vni"] for m in got.get("vniVrfMaps", [])], [1001])  # Guest's VNI map is the template's
        self.assertIn("vniVrfMaps", next(e["note"] for e in ledger if e["item"] == "template vxlan"))
        doc, _ = run({"port": "4789", "vrfId": {}, "vtepIf": ""})
        self.assertEqual([m["vni"] for m in doc["vxlan"]["vniVrfMaps"]], [1001, 1002])
        # a template that sets the VTEP owns the section, as before
        doc, ledger = run({"port": "4789", "vrfId": {}, "vtepIf": "lo5"})
        self.assertNotIn("vxlan", doc)
        self.assertIn("the section is not written", next(e["note"] for e in ledger if e["item"] == "template vxlan"))

    def test_bgp_neighbor_without_evpn_key_before_ecos_9_4_1(self):
        nb = {"192.0.2.2": {"remote_as": 65002, "type": "PE-router", "enable": True, "hold": 180, "ka": 60, "lcl_interface": "", "next_hop_self": False,
                            "password": "", "store_received_routes": False, "bfd_desired": False, "directly_connected": True}}
        sys0 = {"enable": True, "asn": 65001, "rtr_id": "10.0.0.1"}
        out = m_bgpSystemConfig(ctx({"deployment": DEP, "bgp-system": sys0, "bgp-neighbors": nb, "bgp-system-all-vrfs": {"0": sys0}, "bgp-neighbors-all-vrfs": {"0": nb}})[0])
        self.assertIs(out["neighbors"][0]["enableEVPN"], False)

    def test_null_sysconfig_lists_do_not_crash_ctx(self):
        for key in ("roles", "vrfs", "vrfZonesMap", "ifLabels"):
            dep = copy.deepcopy(DEP)
            dep["sysConfig"][key] = None
            Ctx(FakeCap({"deployment": dep}), [])

    def test_ids_mode_comes_from_ids_state_and_is_never_guessed(self):
        profiles = {"Default_S5": ["9.NE"]}
        c, notes = ctx({"ids-profile-state": profiles})
        self.assertIsNone(m_idsIpsConfig(c))  # in no /ids/state list: writing mode Off would disable IDS/IPS on apply
        self.assertEqual(notes[-1]["disposition"], "unresolved")
        self.assertEqual(m_idsIpsConfig(ctx({"ids-profile-state": profiles, "ids-state": {"disabled": ["1.NE"], "ips_inline": ["9.NE"]}})[0]), {"mode": "IPS-Inline", "profile": "Default_S5"})
        self.assertEqual(m_idsIpsConfig(ctx({"ids-profile-state": profiles, "ids-state": {"disabled": ["9.NE"]}})[0])["mode"], "Off")

    def test_string_placeholder_vnis_and_bad_interface_speed(self):
        vx = m_vxlan(ctx({"deployment": DEP, "vxlan": {"port": 4789, "vtepIf": "lo1"}, "vxlan-vni-map": {"0": {"vni": "1001"}, "1": {"vni": "0"}, "2": {"vni": "-1"}}})[0])
        self.assertEqual([m["vni"] for m in vx["vniVrfMaps"]], [1001])
        info = [{"ifname": "wan1", "ifSpeed": "", "ifDuplex": "full", "admin": False}, {"ifname": "wan2", "ifSpeed": "1000", "ifDuplex": "full", "admin": False}]
        self.assertEqual([i["interfaceName"] for i in m_interfaceConfig(ctx({"interface-state": {"ifInfo": info}})[0])["interfaces"]], ["wan2"])

    def test_segment_ospf_bfd_loss_is_ledgered(self):
        iface = {"area": "0.0.0.0", "cost": 1, "priority": 1, "adminStatus": True, "helloInterval": 10, "deadInterval": 40, "transmitDelay": 1, "retransmitInterval": 5,
                 "authType": "None", "authKey": "", "md5Key": 0, "md5Password": "", "comment": "", "bfdDesired": True}
        sysd, area = {"enable": True, "routerId": "1.1.1.1"}, {"0.0.0.0": {"area_type": 0, "redist": False, "summary": False, "translator_role": 0}}
        c, notes = ctx({"deployment": DEP, "ospf-areas": {"0": area, "1": area}, "ospf-system-all-vrfs": {"0": sysd, "1": sysd}, "ospf-interfaces-all-vrfs": {"0": {"lan0": iface}, "1": {}}})
        m_segmentOspfConfig(c)
        self.assertTrue(any("BFD" in n["note"] for n in notes))

    def test_nac_source_ip_interface_without_label_becomes_any(self):
        dep = copy.deepcopy(DEP)
        dep["modeIfs"] = [{"ifName": "lan0", "applianceIPs": [{"vlan": 0, "label": "4"}, {"vlan": 71, "label": ""}]}]
        nac = {"nacEnable": True, "server": {"1": {"address": "192.0.2.5", "authport": 1812, "key": "", "name": "default", "source_ip_interface": "lan0.71"},
                                              "2": {"address": "192.0.2.6", "authport": 1812, "key": "", "name": "s2", "source_ip_interface": "lo1"}},
               "serverGroup": {"1": {"name": "g", "server": "default"}}, "aaaProfile": {"1": {"name": "p"}}, "dot1x": {"1": {"name": "d"}}, "macAuthProfile": {"1": {"name": "m"}},
               "applyPolicies": {"if": {"lan0": {"profile": "p", "auth_type": 1}, "lan0.71": {"profile": "p", "auth_type": 1}, "lan0.72": {"profile": "dot1X", "auth_type": 1}, "vti1": {"profile": "none"}}}}
        out = m_nac(ctx({"deployment": dep, "nac": nac, "loopbacks": {"lo99": {"label": ""}}})[0])
        self.assertEqual([s["source_ip_interface"] for s in out["server"]], ["any", "any"])
        # lan0.71 has no label and lan0.72 no longer exists: only lan0 (label Voice) stays, renumbered from 1
        self.assertEqual([(p["id"], p["auth_interface"]) for p in out["applyPolicies"]], [(1, "Voice")])
        dep["sysConfig"] = dict(DEP["sysConfig"], ifLabels={"lan": [{"id": "4", "name": "Voice"}, {"id": "5", "name": "Data"}], "wan": [{"id": "1", "name": "INETB"}]})
        dep["modeIfs"] = [{"ifName": "lan0", "applianceIPs": [{"vlan": 0, "label": "4"}, {"vlan": 10, "label": "4"}]}, {"ifName": "lan1", "applianceIPs": [{"vlan": 0, "label": "5"}]},
                          {"ifName": "wan1", "applianceIPs": [{"vlan": 100, "label": "1", "wanSide": True}]}]
        nac["applyPolicies"] = {"if": {"lan0": {"profile": "p", "auth_type": 3}, "lan0.10": {"profile": "none", "auth_type": 0}, "lan1": {"profile": "none", "auth_type": 0}, "wan1.100": {"profile": "none", "auth_type": 0}}}
        c, notes = ctx({"deployment": dep, "nac": nac})
        # the WAN entry is left out, and lan0.10 (same label as lan0, different policy) is ledgered
        self.assertEqual(m_nac(c)["applyPolicies"], [{"id": 1, "auth_interface": "Voice", "profile": "p", "auth_type": "mac"}, {"id": 2, "auth_interface": "Data", "auth_type": "trusted"}])
        self.assertTrue(any("lan0.10" in n["item"] and n["disposition"] == "unresolved" for n in notes))
        # the appliance keeps a trusted entry on the RADIUS server's source interface too; /validate rejects that label in both places
        dep["modeIfs"] = [{"ifName": "lan0", "applianceIPs": [{"vlan": 71, "label": "5"}, {"vlan": 72, "label": "4"}, {"vlan": 73, "label": "5"}]}]
        nac["server"] = {"1": dict(nac["server"]["1"], source_ip_interface="lan0.71")}
        nac["applyPolicies"] = {"if": {"lan0.71": {"profile": "none", "auth_type": 0}, "lan0.72": {"profile": "default", "auth_type": 0}, "lan0.73": {"profile": "none", "auth_type": 0}}}
        out = m_nac(ctx({"deployment": dep, "nac": nac})[0])
        self.assertEqual((out["server"][0]["source_ip_interface"], out["applyPolicies"]), ("Data", [{"id": 1, "auth_interface": "Voice", "auth_type": "trusted"}]))
        nac["applyPolicies"] = {"if": {"lan0.71": {"profile": "none", "auth_type": 0}}}
        self.assertIsNone(m_nac(ctx({"deployment": dep, "nac": nac})[0]))

    def test_relay_lease_times_are_ledgered_not_dropped_silently(self):
        # a relay interface keeps an inactive server block with its own lease times; the format's relay entry has no lease fields
        inactive = {"prefix": "0.0.0.0/0", "ipStart": "0.0.0.0", "ipEnd": "0.0.0.0", "gw": [], "dns": [], "netbiosNodeType": "H", "maxLease": 172800, "defaultLease": 86400}
        relay = {"vlan": 0, "label": "4", "wanSide": False, "ip": "10.0.0.1", "mask": 24, "vrf": 0, "zone": 0,
                 "dhcpd": {"type": "relay", "server": inactive, "relay": {"dhcpserver": ["10.9.9.9"], "option82": False, "option82_policy": "append"}}}
        ledger = []
        entry = self._build([relay], ledger=ledger)["deploymentInfo"]["dhcpInfo"][0]
        self.assertNotIn("defaultLease", entry)
        notes = [e for e in ledger if e["disposition"] == "outside-preconfig" and e["target"] == "deploymentInfo.dhcpInfo"]
        self.assertEqual(len(notes), 1)
        self.assertIn("86400", notes[0]["note"])
        self.assertIn("lan0", notes[0]["note"])
        relay["dhcpd"]["server"] = dict(inactive, maxLease=7200, defaultLease=600)  # ECOS defaults: nothing to report
        ledger = []
        self._build([relay], ledger=ledger)
        self.assertFalse([e for e in ledger if e["target"] == "deploymentInfo.dhcpInfo" and e["disposition"] == "outside-preconfig"])

    def test_translate_dhcp_relay_gateway_dual_stack_and_cluster_profile(self):
        relay = {"vlan": 0, "label": "4", "wanSide": False, "ip": "10.0.0.1", "mask": 24, "vrf": 0, "zone": 0,
                 "dhcpd": {"type": "relay", "relay": {"dhcpserver": ["10.9.9.9"], "option82": False, "option82_policy": "append"}}}  # ECOS < 9.5.1: no sub-option keys
        self.assertFalse(self._build([relay])["deploymentInfo"]["dhcpInfo"][0]["option82SubOptions150"])
        srv = {"prefix": "10.0.0.0/24", "ipStart": "10.0.0.10", "ipEnd": "10.0.0.200", "gw": [], "dns": [], "netbiosNodeType": "B", "maxLease": 86400, "defaultLease": 3600}
        server = dict(relay, dhcpd={"type": "server", "server": srv})
        self.assertIsNone(self._build([server])["deploymentInfo"]["dhcpInfo"][0]["gatewayIpAddress"])
        wan = {"vlan": 0, "label": "1", "wanSide": True, "vrf": 0, "zone": 0, "harden": 1, "behindNAT": "none", "maxBW": {"outbound": 50000}, "intf_mode": "static_slaac"}
        ifs = self._build([dict(wan, version=4, ip="198.51.100.10", mask=24, wanNexthop="198.51.100.1"), dict(wan, version=6, ip="", mask=0, wanNexthop="")], "wan0")["deploymentInfo"]["deploymentInterfaces"]
        self.assertEqual([(i["addressingMode"], i["ipAddressMask"]) for i in ifs], [("static", "198.51.100.10/24"), ("slaac", None)])
        out = self._build([], **{"cluster-profiles": [{"id": 3, "name": "HA-Pair"}], "cluster-profile-mapping": {"3": ["S1"]}})
        self.assertEqual(out["applianceInfo"]["clusterProfile"], "HA-Pair")

    def test_branch_nat_without_deployment_info_is_rejected_before_validate(self):
        from validate import apply_time_error, validate_text

        class Client:
            write_requests = 0
            calls = 0

            def request(self, *a, **k):
                Client.calls += 1
                return b""
        nat = "branchNatMapsConfig:\n  branchNatRules:\n  - priorityLevel: 90\n"
        verdict = validate_text(Client(), nat)
        self.assertEqual((verdict["accepted"], Client.calls), (False, 0))
        self.assertIn("deploymentInfo", verdict["error"])
        self.assertTrue(validate_text(Client(), "deploymentInfo:\n  deploymentMode: inline-router\n" + nat)["accepted"])
        self.assertIn("placeholder", validate_text(Client(), "ikeConfig:\n  presharedKey: '<SECRET:$.psk>'\n")["error"])
        ike = "tunnelConfiguration:\n  tunnels:\n  - tunnelName: t1\n    ikeConfig: {{ikeVersion: {}, localIkeIdentifier: {}, remoteIkeIdentifier: 192.0.2.2}}\n"
        self.assertIn("IKEv2", validate_text(Client(), ike.format(2, "null"))["error"])  # /validate answers HTTP 500
        self.assertIsNone(apply_time_error(ike.format(1, "null")))
        self.assertIsNone(apply_time_error(ike.format(2, "192.0.2.1")))
        psk = "tunnelConfiguration:\n  tunnels:\n  - tunnelName: t2\n    tunnelEncap: ipsec\n    ikeConfig: {{ikeVersion: 1, presharedKey: '{}'}}\n"
        self.assertIn("presharedKey", apply_time_error(psk.format("")))  # render and /validate accept it, apply fails
        self.assertIsNone(apply_time_error(psk.format("Test-Only-Key-1")))
        noencap = "tunnelConfiguration:\n  tunnels:\n  - tunnelName: t3\n    tunnelEncap: no_encap\n    remoteIp: {}\n"
        self.assertIn("remoteIp", apply_time_error(noencap.format("null")))
        self.assertIsNone(apply_time_error(noencap.format("198.51.100.9")))
        natrule = "deploymentInfo:\n  deploymentMode: inline-router\nbranchNatMapsConfig:\n  branchNatRules:\n  - priorityLevel: 10\n    interfaceName: {}\n"
        self.assertIn("VLAN subinterface", apply_time_error(natrule.format("lan1.55")))
        self.assertIsNone(apply_time_error(natrule.format("lan0")))
        self.assertIn("WAN interface", apply_time_error(natrule.format("wan1")))
        self.assertIsNone(apply_time_error(natrule.format("any")))
        self.assertEqual(Client.calls, 1)

    def test_local_routes_carry_subnet_sharing_flags_without_routes(self):
        from mappers import m_localRoutes
        vrf0 = {"self": 0, "add_local_asn": True, "add_local_communities": True, "add_local_lan": True, "add_local_metric": 55, "add_local_wan": False,
                "local_asn_filter": True, "local_communities": "100:101", "rtmap_to_subshare": "default_rtmap_to_subsh"}
        c, notes = ctx({"deployment": DEP, "system-info": {"auto_subnet": {"vrf": {"0": vrf0}}}, "subnets": {"subnets": {"entries": []}}})
        self.assertEqual(m_localRoutes(c), {"advertiseLocalLanSubnets": True, "advertiseLocalWanSubnets": False, "localMetric": 55, "localCommunities": "100:101",
                                            "filterRoutesWithLocalASN": True, "redistToSDwanFabricRouteMap": "default_rtmap_to_subsh", "routes": []})
        self.assertIn("add_local_asn", " ".join(n["note"] for n in notes if n["disposition"] == "outside-preconfig"))  # no preconfig field exists for it
        self.assertNotIn("add_local_asn", " ".join(n["note"] for n in notes if n["disposition"] == "unmapped-source-key"))
        c, _ = ctx({"deployment": DEP, "system-info": {"auto_subnet": {"vrf": {"0": dict(vrf0, add_local_communities=False)}}}, "subnets": {"subnets": {"entries": []}}})
        self.assertEqual(m_localRoutes(c)["localCommunities"], "")  # communities are kept but not added
        c, _ = ctx({"deployment": DEP, "subnets": {"subnets": {"entries": []}}})
        self.assertIsNone(m_localRoutes(c))
        route = {"configured": True, "local": True, "automatic": False, "prefix": "198.51.100.0/24", "nextHop": "", "ifName": "lan0.72", "metric": 50, "advert": True,
                 "advert_bgp": False, "advert_ospf": False, "zone_id": "65534", "label": "0"}
        c, notes = ctx({"deployment": DEP, "subnets": {"subnets": {"entries": [{"state": route}, {"state": dict(route, prefix="203.0.113.0/24", nextHop="192.0.2.1")}]}}})
        self.assertEqual([r["routeIpSubnet"] for r in m_localRoutes(c)["routes"]], ["203.0.113.0/24"])  # interface-only route fails at apply
        self.assertTrue(any(n["disposition"] == "unresolved" and "198.51.100.0/24" in n["note"] for n in notes))

    def test_routes_take_advert_flags_and_comment_from_the_configured_table(self):
        from mappers import m_localRoutes
        route = {"configured": True, "local": True, "automatic": False, "prefix": "203.0.113.0/24", "nextHop": "192.0.2.250", "ifName": "lan0.201", "metric": 50, "advert": True,
                 "advert_bgp": False, "advert_ospf": False, "zone_id": "65534", "label": "0"}
        configured = {"prefix": {"203.0.113.0/24": {"advert": True, "advert_bgp": True, "advert_ospf": False, "nhop": {"192.0.2.250": {"interface": {"lan0.201": {"comment": "printers", "dir": "FROM_LAN"}}}}}}}
        c, _ = ctx({"deployment": DEP, "subnets": {"subnets": {"entries": [{"state": route}]}}, "static-routes-configured": configured})
        r = m_localRoutes(c)["routes"][0]
        self.assertEqual((r["advertiseToBgp"], r["comment"], r["tag"]), (True, "printers", "FROM_LAN"))  # /subnets reports advert_bgp false and has no comment
        c, _ = ctx({"deployment": DEP, "subnets": {"subnets": {"entries": [{"state": route}]}}})
        self.assertNotIn("comment", m_localRoutes(c)["routes"][0])

    def test_next_hop_zero_route_is_written_from_its_config(self):
        from mappers import m_localRoutes
        st = {"configured": True, "local": True, "automatic": False, "prefix": "0.0.0.0/0", "nextHop": "", "ifName": "", "metric": 50, "advert": True,
              "advert_bgp": False, "advert_ospf": False, "zone_id": "65534", "label": "0"}
        conf = {"prefix": "0.0.0.0/0", "nextHop": "0.0.0.0", "ifName": "default", "comment": "", "tag": "ANY", "gms_marked": False}
        configured = {"prefix": {"0.0.0.0/0": {"advert": True, "nhop": {"0.0.0.0": {"interface": {"default": {"dir": "ANY", "comment": "hub default"}}}}}}}
        c, _ = ctx({"deployment": DEP, "subnets": {"subnets": {"entries": [{"state": st, "config": conf}]}}, "static-routes-configured": configured})
        r = m_localRoutes(c)["routes"][0]
        self.assertEqual((r["nextHop"], r["interfaceName"], r["advertise"], r["comment"], r["tag"]), ("0.0.0.0", None, True, "hub default", "ANY"))
        for entry in ({"state": st, "config": dict(conf, gms_marked=True)}, {"state": st}):  # Orchestrator-made, or no config to read
            c, _ = ctx({"deployment": DEP, "subnets": {"subnets": {"entries": [entry]}}})
            self.assertIsNone(m_localRoutes(c))

    def test_default_interface_route_is_not_pinned_to_the_interface_in_use(self):
        from mappers import m_localRoutes
        st = {"configured": True, "local": True, "automatic": False, "prefix": "198.51.100.0/24", "nextHop": "192.0.2.1", "ifName": "wan1", "metric": 50, "advert": False,
              "advert_bgp": False, "advert_ospf": False, "zone_id": "65534", "label": "0"}
        c, _ = ctx({"deployment": DEP, "subnets": {"subnets": {"entries": [{"state": st, "config": {"nextHop": "192.0.2.1", "ifName": "default"}}]}}})
        self.assertIsNone(m_localRoutes(c)["routes"][0]["interfaceName"])
        c, _ = ctx({"deployment": DEP, "subnets": {"subnets": {"entries": [{"state": st, "config": {"nextHop": "192.0.2.1", "ifName": "lan0"}}]}}})
        self.assertEqual(m_localRoutes(c)["routes"][0]["interfaceName"], "lan0")
        c, _ = ctx({"deployment": DEP, "subnets": {"subnets": {"entries": [{"state": st, "config": {"nextHop": "192.0.2.1", "ifName": "lan0", "gms_marked": True}}]}}})
        self.assertIsNone(m_localRoutes(c))  # an Orchestrator-made route with a real next hop (third-party cloud integration) is not a static route
        dep = dict(DEP, sysConfig=dict(DEP["sysConfig"], vrfZonesMap={"0": {"1": {"id": 1, "name": "WAN"}}}))
        entry = {"state": dict(st, zone_id="1"), "config": {"nextHop": "192.0.2.1", "ifName": "default", "zone_id": 65534}}
        c, _ = ctx({"deployment": dep, "subnets": {"subnets": {"entries": [entry]}}})
        self.assertIsNone(m_localRoutes(c)["routes"][0]["zone"])  # the zone of wan1 is not the route's zone
        c, _ = ctx({"deployment": dep, "subnets": {"subnets": {"entries": [{"state": entry["state"]}]}}})
        self.assertEqual(m_localRoutes(c)["routes"][0]["zone"], "WAN")  # no config: the state's zone

    def test_disabled_segment_instances_are_ledgered_not_silent(self):
        dep = {"sysConfig": dict(DEP["sysConfig"], vrfs=[{"id": "0", "name": "Default"}, {"id": "1", "name": "corp"}, {"id": "2", "name": "guest"}]), "modeIfs": DEP["modeIfs"]}
        system = {"enable": True, "asn": 65001, "rtr_id": "192.0.2.1", "route_target": {}}
        c, notes = ctx({"deployment": dep, "bgp-system-all-vrfs": {"0": system, "1": dict(system, asn=65101), "2": dict(system, enable=False)},
                        "bgp-neighbors-all-vrfs": {}})
        self.assertEqual([v["segment"] for v in m_segmentBgpSystems(c)], ["Default", "corp"])
        self.assertTrue(any(n["item"] == "bgp-system-all-vrfs[2]" and "guest" in n["note"] for n in notes))

    def test_disabled_ospf_segment_is_ledgered_when_no_segment_runs_ospf(self):
        from mappers import m_segmentOspfConfig
        dep = {"sysConfig": dict(DEP["sysConfig"], vrfs=[{"id": "0", "name": "Default"}, {"id": "1", "name": "corp"}]), "modeIfs": DEP["modeIfs"]}
        c, notes = ctx({"deployment": dep, "ospf-system-all-vrfs": {"0": {"enable": True}, "1": {"enable": False, "routerId": "192.0.2.1"}}, "ospf-interfaces-all-vrfs": {}})
        self.assertIsNone(m_segmentOspfConfig(c))
        self.assertTrue(any(n["item"] == "ospf-system-all-vrfs[1]" and "corp" in n["note"] for n in notes))

    def test_disabled_ospf_segment_with_interfaces_is_carried_disabled(self):
        from mappers import m_ospfSystemConfig, m_segmentOspfConfig
        dep = {"sysConfig": dict(DEP["sysConfig"], vrfs=[{"id": "0", "name": "Default"}, {"id": "1", "name": "corp"}]), "modeIfs": DEP3["modeIfs"]}
        iface = {"area": "0.0.0.0", "cost": 10, "priority": 1, "adminStatus": True, "helloInterval": 10, "deadInterval": 40, "transmitDelay": 1, "retransmitInterval": 5,
                 "authType": "None", "authKey": "", "md5Key": 0, "md5Password": "", "comment": "", "bfdDesired": False}
        area = {"0.0.0.0": {"area_type": 0, "redist": False, "summary": False, "translator_role": 0}}
        data = {"deployment": dep, "ospf-areas": {"0": area, "1": area}, "ospf-interfaces-all-vrfs": {"0": {"lan0": iface}, "1": {"lan0.72": iface}},
                "ospf-system-all-vrfs": {"0": {"enable": True, "routerId": "192.0.2.1"}, "1": {"enable": False, "routerId": "192.0.2.2", "redistMapToOSPF": "corp_rtmap_to_ospf"}}}
        out = {e["segment"]: e for e in m_segmentOspfConfig(ctx(data)[0]) or []}
        self.assertEqual(sorted(out), ["Default", "corp"])  # the dormant corp OSPF is kept, switched off as on the source
        self.assertEqual((out["corp"]["enable"], out["corp"]["routerId"], [i["interfaceName"] for i in out["corp"]["interfaces"]]), (False, "192.0.2.2", ["lan0.72"]))
        self.assertIsNone(m_ospfSystemConfig(ctx(data)[0]))  # Orchestrator ignores ospfSystemConfig once segmentOspfConfig is present

    def test_segment_routes_take_comment_from_route_config_not_the_default_table(self):
        from mappers import m_segmentLocalRoutes
        dep = {"sysConfig": dict(DEP["sysConfig"], vrfs=[{"id": "0", "name": "Default"}, {"id": "1", "name": "corp"}]), "modeIfs": DEP["modeIfs"]}
        st = {"configured": True, "local": True, "automatic": False, "prefix": "203.0.113.0/24", "nextHop": "192.0.2.250", "ifName": "lan0.203", "metric": 50, "advert": True,
              "advert_bgp": False, "advert_ospf": False, "zone_id": "65534", "label": "0"}
        configured = {"prefix": {"203.0.113.0/24": {"advert_bgp": True, "nhop": {"192.0.2.250": {"interface": {"lan0.203": {"comment": "default route"}}}}}}}  # same prefix, Default segment
        c, notes = ctx({"deployment": dep, "static-routes-configured": configured,
                        "subnets-all-vrfs": {"subnets": {"1": {"entries": [{"state": st, "config": {"comment": "corp app", "tag": "FROM_WAN"}}]}}}})
        r = m_segmentLocalRoutes(c)[0]["routes"][0]
        self.assertEqual((r["advertiseToBgp"], r["comment"], r["tag"]), (False, "corp app", "FROM_WAN"))
        self.assertEqual(len([n for n in notes if n["item"] == "subnets-all-vrfs[1]"]), 1)  # route_list runs twice here

    def test_segment_without_routes_keeps_its_subnet_sharing(self):
        from mappers import m_localRoutes, m_segmentLocalRoutes
        dep = {"sysConfig": dict(DEP["sysConfig"], vrfs=[{"id": "0", "name": "Default"}, {"id": "1", "name": "corp"}]), "modeIfs": DEP["modeIfs"]}
        sharing = {"add_local_lan": True, "add_local_wan": False, "add_local_metric": 50, "local_asn_filter": True, "rtmap_to_subshare": "to_fabric"}
        st = {"configured": True, "local": True, "automatic": False, "prefix": "203.0.113.0/24", "nextHop": "192.0.2.250", "ifName": "lan0", "metric": 50, "advert": True,
              "advert_bgp": False, "advert_ospf": False, "zone_id": "65534", "label": "0"}
        c, _ = ctx({"deployment": dep, "system-info": {"auto_subnet": {"vrf": {"0": sharing, "1": sharing}}},
                    "subnets": {"subnets": {"entries": [{"state": st}]}}, "subnets-all-vrfs": {"subnets": {"0": {"entries": [{"state": st}]}}}})
        self.assertIsNone(m_localRoutes(c))  # corp has settings of its own, so every segment goes in segmentLocalRoutes
        out = {e["segment"]: e for e in m_segmentLocalRoutes(c)}
        self.assertEqual(len(out["Default"]["routes"]), 1)
        self.assertEqual((out["corp"]["routes"], out["corp"]["advertiseLocalLanSubnets"], out["corp"]["filterRoutesWithLocalASN"], out["corp"]["redistToSDwanFabricRouteMap"]),
                         ([], True, True, "to_fabric"))

    def test_default_valued_segment_is_left_out_and_no_route_map_is_noted(self):
        from mappers import m_segmentLocalRoutes
        dep = {"sysConfig": dict(DEP["sysConfig"], vrfs=[{"id": "0", "name": "Default"}, {"id": "1", "name": "corp"}, {"id": "2", "name": "iot"}]), "modeIfs": DEP["modeIfs"]}
        plain = {"add_local_lan": False, "add_local_wan": False, "add_local_metric": 50, "local_asn_filter": False, "rtmap_to_subshare": ""}
        c, notes = ctx({"deployment": dep, "system-info": {"auto_subnet": {"vrf": {"0": plain, "1": dict(plain, add_local_lan=True), "2": plain}}}, "subnets-all-vrfs": {"subnets": {}}})
        out = {e["segment"]: e for e in m_segmentLocalRoutes(c)}
        self.assertEqual(sorted(out), ["Default", "corp"])  # writing iot would make Orchestrator add default_rtmap_to_subsh
        self.assertNotIn("redistToSDwanFabricRouteMap", out["corp"])  # omitted, null and "" all become default_rtmap_to_subsh; never "none"
        self.assertTrue(any("default_rtmap_to_subsh" in n["note"] and n["target"].startswith("segmentLocalRoutes") for n in notes))
        trimmed = {"segmentLocalRoutes": [dict(e) for e in out.values()]}
        drop_template_fields(trimmed, {"routes": {"1": {"advertiseLocalLanSubnets"}}}, {"0": "Default", "1": "corp"}, lambda *a: None)
        self.assertEqual([e["segment"] for e in trimmed["segmentLocalRoutes"]], ["Default"])  # corp has only default values left once the template's field is out

    def test_http_ip_sla_keeps_proxy_and_user_agent(self):
        from mappers import m_ipSlaRule
        op = {"type": "http-monitor", "http-monitor-url": "www.example.com", "port-name": "wan1", "http-timeout": "30", "proxyAddress": "192.0.2.9", "proxyPort": "3128", "user-agent": "Mozilla/5.0"}
        c, _ = ctx({"deployment": DEP, "ipsla-managers": {"MGR_1": {"enable": True, "interval": 10, "comment": "", "routeLabelId": 0, "operation": {"OPR_1": op}}}})
        m = m_ipSlaRule(c)["ruleEntries"][0]["ipslaMonitor"]
        self.assertEqual((m["proxyAddress"], m["proxyPort"], m["userAgent"]), ("192.0.2.9", 3128, "Mozilla/5.0"))
        rule = {"enable": True, "interval": "10", "comment": "", "routeLabelId": 0, "upAction": "def-subnet", "operation": {"OPR_2": {"type": "port-monitor", "port-name": "wan1"}},
                "downAction": {"DN_ACTION_subnet-adv_3": {"type": "subnet-adv", "port-name": "lan0.201"}}}
        c2, notes = ctx({"deployment": DEP, "ipsla-managers": {"MGR_2": rule}})
        r = m_ipSlaRule(c2)["ruleEntries"][0]
        self.assertEqual((r["downAction"], r["upAction"]), ({"downActionType": "advertiseSubnet", "interfaceName": "lan0.201"}, {"upActionType": "defaultSubnetAction"}))
        rule["downAction"] = {"DN_ACTION_vrrp-prio_dec_7": {"dec": "20", "type": "vrrp-prio", "port-name": "lan0.202"}}
        rule["upAction"] = {"UP_ACTION_vrrp-prio_inc_8": {"type": "vrrp-prio", "port-name": "lan0.202", "inc": "20"}}
        r = m_ipSlaRule(ctx({"deployment": DEP, "ipsla-managers": {"MGR_2": rule}})[0])["ruleEntries"][0]
        self.assertEqual((r["downAction"], r["upAction"]), ({"downActionType": "decreaseVRRPPriority", "interfaceName": "lan0.202", "priority": 20},
                                                            {"upActionType": "increaseVRRPPriority", "interfaceName": "lan0.202", "priority": 20}))
        for dn, want in (({"type": "subnet-share"}, {"downActionType": "disableSubnetSharing"}),
                         ({"type": "subnet-rmv", "port-name": "lan0.204"}, {"downActionType": "removeAutoSubnet", "interfaceName": "lan0.204"})):
            rule["downAction"] = {"DN_ACTION_x_1": dn}
            self.assertEqual(m_ipSlaRule(ctx({"deployment": DEP, "ipsla-managers": {"MGR_2": rule}})[0])["ruleEntries"][0]["downAction"], want)
        rule["downAction"] = {"DN_ACTION_x_1": {"type": "made-up"}}
        c2, notes = ctx({"deployment": DEP, "ipsla-managers": {"MGR_2": rule}})
        m_ipSlaRule(c2)
        self.assertTrue(any("made-up" in n["note"] for n in notes))  # an unmapped action is ledgered, not silently an alarm
        ping = {"type": "ip-monitor", "ip-monitor-ip": "192.0.2.1", "src-port-name": "wan1", "force-dns": "true", "metric-combination": "metric-and"}
        dep = dict(DEP, modeIfs=[{"ifName": "wan1", "applianceIPs": [{"vlan": 0, "ip": "198.51.100.11", "label": ""}]}])
        tunnels = {"t1": {"alias": "pt_gre", "sourceIpAddress": "198.51.100.11"}, "t2": {"alias": "other", "sourceIpAddress": "198.51.100.99"}}
        data = {"deployment": dep, "passthrough-tunnels": tunnels, "ipsla-managers": {"MGR_3": dict(rule, operation={"OPR_1": ping})}}
        m = m_ipSlaRule(ctx(data)[0])["ruleEntries"][0]["ipslaMonitor"]
        self.assertEqual((m["sourceInterfaceName"], m["tunnelName"], m["forceDnsThroughProbePath"], m["metricCombination"]), ("wan1", "pt_gre", True, "metric-and"))
        tunnels["t2"]["sourceIpAddress"] = "198.51.100.11"  # two candidate tunnels: the rule is not guessed
        self.assertIsNone(m_ipSlaRule(ctx(data)[0]))
        del op["proxyAddress"], op["user-agent"]
        self.assertFalse({"proxyAddress", "proxyPort", "userAgent"} & set(m_ipSlaRule(c)["ruleEntries"][0]["ipslaMonitor"]))

    def test_peer_priority_list_template_owns_the_peer_priority_section(self):
        from translate import selected_templates
        cap = FakeCap({"template-association": {"templateIds": ["g"]}, "template-groups": [{"name": "g", "selectedTemplateNames": ["peerPriorityList", "dns"]}]})
        self.assertEqual(selected_templates(cap), {"peerPriority", "dns"})

    def test_overlay_hub_membership_is_ledgered(self):
        cap = FakeCap({"appliance": {"hostName": "h1", "groupId": "1.Network", "site": "S1", "networkRole": "1"}, "deployment": dict(DEP, modeIfs=[]),
                       "overlay-config": [{"id": 1, "name": "Mesh", "topology": {"hubs": []}}, {"id": 4, "name": "Default", "topology": {"hubs": ["9.NE", "2.NE"]}}],
                       "overlay-association": {"1": ["9.NE"], "4": ["9.NE"]}})
        cap.folder = "fake"
        ledger: list = []
        self.assertEqual(build(cap, ledger)["businessIntentOverlays"], {"overlays": ["Mesh", "Default"]})
        self.assertEqual([e["note"] for e in ledger if e["item"] == "overlay-config.topology.hubs"][0][:26], "hub in overlays Default: h")

    def test_ra_info_keeps_prefixes_and_skips_ipv4(self):
        ra = {"self": "lan0.90", "hoplimit": 64, "linkmtu": 1500, "managedflag": False, "maxinterval": 600, "mininterval": 200, "otherconfigflag": True, "reachabletime": 30000,
              "retranstimer": 1000, "routerdeflifetime": 1800, "routerpreference": "high", "sendadv": True,
              "prefix_id": {"3": {"self": 3, "autonomous": False, "onlink": True, "prefix": "2001:db8:3::/64", "prefixvalidlifetime": 0, "prfrdlifetime": 0},
                            "1": {"self": 1, "autonomous": True, "onlink": True, "prefix": "2001:db8:1::/64", "prefixvalidlifetime": 86400, "prfrdlifetime": 14400}}}
        lan = {"label": "", "wanSide": False, "mask": 64, "vrf": 0, "zone": 0, "version": 6, "ra": ra}
        di = self._build([dict(lan, vlan=90, ip="2001:db8:1::1"), dict(lan, vlan=91, ip="10.0.0.1", mask=24, version=4)])["deploymentInfo"]
        self.assertEqual([r["raInterfaceName"] for r in di["raInfo"]], ["lan0.90"])
        self.assertEqual([(p["id"], p["prefix"], p["prefixvalidlifetime"]) for p in di["raInfo"][0]["prefix_id"]], [(1, "2001:db8:1::/64", 86400), (3, "2001:db8:3::/64", 0)])

    def test_dhcp_failover_maps_to_dhcp_ha_once_per_physical_interface(self):
        srv = {"prefix": "10.0.0.0/24", "ipStart": "10.0.0.10", "ipEnd": "10.0.0.200", "gw": [], "dns": [], "netbiosNodeType": "B", "maxLease": 86400, "defaultLease": 3600, "failover": True}
        lan = {"label": "", "wanSide": False, "ip": "10.0.0.1", "mask": 24, "vrf": 0, "zone": 0, "dhcpd": {"type": "server", "server": srv}}
        dep = copy.deepcopy(DEP)
        dep["modeIfs"] = [{"ifName": "lan0", "applianceIPs": [dict(lan, vlan=71), dict(lan, vlan=72)]},
                          {"ifName": "lan1", "applianceIPs": [dict(lan, dhcpd={"type": "server", "server": dict(srv, failover=False)})]}]
        fo = {"load_bal_max": 5, "max_resp_delay": 10, "max_unack_updates": 10, "mclt": 3600, "my_ip": "10.0.0.1", "my_port": 647, "peer_ip": "10.0.0.2", "peer_port": 647, "role": "primary", "split": 128}
        dep["dhcpFailover"] = {"lan0": dict(fo, dhcp_fo_rel_name="fo-lan0"), "lan1": fo}  # lan1: stale settings, its server has failover off
        cap = FakeCap({"appliance": {"hostName": "h1", "groupId": "1.Network", "site": "S1", "networkRole": "0"}, "deployment": dep})
        cap.folder = "fake"
        ledger: list = []
        dhcp = build(cap, ledger)["deploymentInfo"]["dhcpInfo"]
        self.assertEqual([("dhcpHA" in d) for d in dhcp], [True, False, False])
        self.assertEqual(dhcp[0]["dhcpHA"], {"dhcpFailoverRole": "primary", "ipAddress": "10.0.0.1", "ipAddressPort": 647, "peerIpAddress": "10.0.0.2", "peerIpAddressPort": 647,
                                             "mclt": 3600, "split": 128, "maxResponseDelay": 10, "maxUnackedUpdates": 10, "loadBalanceMaxSeconds": 5, "foRelationshipName": "fo-lan0"})
        self.assertEqual(sorted(e["disposition"] for e in ledger if e["item"] == "deployment.dhcpFailover"), ["mapped", "runtime"])

    def test_corpus_skips_partial_only_captures(self):
        import json, tempfile
        from corpus import latest
        root = Path(tempfile.mkdtemp())
        for stamp, only in (("20261017T0800Z", None), ("20261017T0900Z", ["ids-state"]), ("20261016T0700Z", None)):
            (root / stamp).mkdir()
            (root / stamp / "run.json").write_text(json.dumps({"only": only}))
        self.assertEqual(latest(root).name, "20261017T0800Z")
        (root / "20261017T1000Z").mkdir()  # newer but taken while the appliance was unreachable
        (root / "20261017T1000Z" / "run.json").write_text(json.dumps({"only": None, "reachable": False}))
        self.assertEqual(latest(root).name, "20261017T0800Z")

    def test_branch_nat_zero_address_and_pool_reference(self):
        maps = {"map1": {"prio": {"10": {"dir": "outbound", "enable": True, "match": {"intf": "lan0", "segment": "0", "proto": "any", "src_subnet": "0.0.0.0/0", "dst_subnet": "198.51.100.0/24"},
                                         "set": {"trans_src": "41"}}}}}
        pools = {"7": {"dir": "outbound", "name": "p7", "pat": 1, "segment": "0", "subnet": "203.0.113.7/32", "comment": ""},
                 "41": {"dir": "outbound", "name": "p41", "pat": 1, "segment": "0", "subnet": "203.0.113.41/32", "comment": ""}}
        rule = m_branchNatMapsConfig(ctx({"deployment": DEP, "branch-nat-maps": maps, "nat-pools": pools})[0])["branchNatRules"][0]
        self.assertEqual((rule["sourceIpSubnet"], rule["translateNatPoolID"]), ("any", 1))  # pool 41 is the second natPools entry
        self.assertNotIn("translateSourceIpSubnet", rule)
        # names only ({"map1": "map1"}): no rules, nothing written, the ledger names the map
        c, notes = ctx({"deployment": DEP, "branch-nat-maps": {"map1": "map1"}})
        self.assertIsNone(m_branchNatMapsConfig(c))
        nat_notes = [n for n in notes if n["item"] == "branch-nat-maps"]
        self.assertEqual([n["disposition"] for n in nat_notes], ["default-omitted"])
        self.assertIn("map1", nat_notes[0]["note"])
        c, notes = ctx({"deployment": DEP, "branch-nat-maps": {}})
        self.assertIsNone(m_branchNatMapsConfig(c))
        self.assertEqual([n["disposition"] for n in notes if n["item"] == "branch-nat-maps"], ["default-omitted"])

    def test_branch_nat_reads_live_rules_when_cached_lists_names_only(self):
        # seen on 9.6.2.1 and 9.7.1 right after an apply: Orchestrator's cached /nat/maps lags the appliance
        import json
        import tempfile
        from translate import Capture
        rule = {"dir": "outbound", "enable": True, "match": {"intf": "any", "segment": "0", "proto": "any", "src_subnet": "192.0.2.0/24"}, "set": {"trans_src": "198.51.100.0/24"}}
        copies = {"cached": {"map1": "map1"}, "live": {"map1": {"prio": {"10": rule}}}}
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "capture").mkdir()
            (folder / "run.json").write_text(json.dumps({"appliance": {"nePk": "2.NE"}}))
            index = [{"id": "deployment", "label": "live", "status": "ok", "file": "capture/deployment.json"}]
            (folder / "capture/deployment.json").write_text(json.dumps({"data": DEP}))
            for label, data in copies.items():  # cached first, as capture.py writes the index
                index.append({"id": "branch-nat-maps", "label": label, "status": "ok", "file": "capture/branch-nat-maps.{}.json".format(label)})
                (folder / "capture/branch-nat-maps.{}.json".format(label)).write_text(json.dumps({"data": data}))
            (folder / "capture-index.json").write_text(json.dumps(index))
            notes = []
            nat = m_branchNatMapsConfig(Ctx(Capture(folder), notes))
        self.assertEqual([(r["priorityLevel"], r["translateSourceIpSubnet"]) for r in nat["branchNatRules"]], [(10, "198.51.100.0/24")])
        self.assertEqual([n["disposition"] for n in notes if n["item"] == "branch-nat-maps"], ["mapped"])

    def test_ids_profile_is_substituted_by_signature_family(self):
        inv = {"segments": ["Default"], "zones": ["Default"], "lan": ["L"], "wan": ["W"], "groups": ["g"], "templateGroups": ["t"], "overlays": ["o"],
               "idsProfiles": ["Default", "Default_S5", "Default_S7"]}
        notes = []
        self.assertEqual(substitute({"idsIpsConfig": {"mode": "IPS-Performant", "profile": "Custom_S7"}}, inv, notes)["idsIpsConfig"]["profile"], "Default_S7")
        self.assertEqual(substitute({"idsIpsConfig": {"mode": "Off", "profile": "Default_S5"}}, inv)["idsIpsConfig"]["profile"], "Default_S5")
        self.assertTrue(notes)

    def test_route_labels_are_substituted_for_the_validator(self):
        inv = {"segments": ["Default"], "zones": ["Default"], "lan": ["L"], "wan": ["W"], "groups": ["g"], "templateGroups": ["t"], "overlays": ["o"],
               "routeLabels": ["Internet", "Lab label"]}
        doc = {"segmentLocalRoutes": [{"segment": "Default", "routes": [{"routeIpSubnet": "0.0.0.0/0", "routeLabel": "Internet"}, {"routeIpSubnet": "192.0.2.0/24", "routeLabel": "Backup"}]}]}
        out = substitute(doc, inv)
        self.assertEqual([r["routeLabel"] for r in out["segmentLocalRoutes"][0]["routes"]], ["Internet", "Internet"])  # an unknown name takes the validator's first label

    def test_suite_loads_the_shipped_constraints(self):
        self.assertTrue(load_constraints())



class IsolationCheck:
    def check(self, mapper, data, pick, good, section):
        c, notes = ctx(data)
        out = mapper(c)
        self.assertIsNotNone(out, "the whole section was dropped")
        self.assertEqual(pick(out), good)
        self.assertEqual([n["target"] for n in notes if n["disposition"] == "toolkit-error"], [section])


class ItemIsolation(IsolationCheck, unittest.TestCase):
    """One malformed item is ledgered as toolkit-error and skipped; the rest of its section is still written."""

    def test_vrrp_group(self):
        from mappers import m_vrrp
        g = {"groupId": 1, "interface": "lan0", "enable": "Up", "vipaddr": "192.0.2.1", "adv_timer": 1, "priority": 100, "version": 2, "preempt": True, "pkt_trace": False, "holddown": 10}
        bad = {k: v for k, v in dict(g, groupId=2).items() if k != "priority"}
        self.check(m_vrrp, {"vrrp": [g, bad]}, lambda o: [e["groupId"] for e in o["vrrpEntries"]], [1], "vrrp")

    def test_loopback(self):
        from mappers import m_loopbackInterface
        lo = {"admin": True, "ipaddr": "192.0.2.9", "nmask": 32, "label": "", "vrf_id": 0, "zone": 0}
        self.check(m_loopbackInterface, {"deployment": DEP, "loopbacks": {"lo1": lo, "lo2": {"admin": True}}}, lambda o: [x["interfaceId"] for x in o["loopbacks"]], ["lo1"], "loopbackInterface")

    def test_bgp_neighbor(self):
        from mappers import m_bgpSystemConfig
        n = {"remote_as": 65001, "type": "Branch", "enable": True, "hold": 180, "ka": 60, "next_hop_self": False, "store_received_routes": True, "directly_connected": True}
        data = {"deployment": DEP, "bgp-system": {"enable": True, "asn": 65000}, "bgp-neighbors": {"192.0.2.1": n, "192.0.2.2": {"type": "Branch"}}}
        self.check(m_bgpSystemConfig, data, lambda o: [x["peerIpAddress"] for x in o["neighbors"]], ["192.0.2.1"], "bgpSystemConfig.neighbors")

    def test_port_forwarding_rule(self):
        from mappers import m_inboundPortForwarding
        r = {"srcSubnet": "0.0.0.0/0", "destSubnet": "192.0.2.10/32", "destPort": "443", "protocol": "tcp", "targetIp": "", "targetPort": "", "srcIf": "any", "vrf_id": 0, "comment": ""}
        self.check(m_inboundPortForwarding, {"deployment": DEP, "port-forwarding": [r, {"srcIf": "any", "comment": ""}]}, lambda o: len(o["portForwardingRules"]), 1, "inboundPortForwarding")

    def test_ip_sla_rule(self):
        from mappers import m_ipSlaRule
        op = {"type": "ip-monitor", "ip-monitor-ip": "192.0.2.98"}
        good = {"enable": True, "interval": "10", "comment": "", "upAction": "def-alarm", "downAction": "alarm", "operation": {"OPR_1": op}}
        bad = dict(good, interval="every minute")
        self.check(m_ipSlaRule, {"deployment": DEP, "ipsla-managers": {"MGR_1": good, "MGR_2": bad}}, lambda o: len(o["ruleEntries"]), 1, "ipSlaRule")

    def test_local_route(self):
        from mappers import m_localRoutes
        st = {"configured": True, "local": True, "automatic": False, "prefix": "198.51.100.0/24", "nextHop": "192.0.2.254", "ifName": "lan0", "metric": 50, "advert": True, "advert_bgp": False, "advert_ospf": False}
        bad = {k: v for k, v in dict(st, prefix="203.0.113.0/24").items() if k != "metric"}
        data = {"deployment": DEP, "subnets": {"subnets": {"entries": [{"state": st}, {"state": bad}]}}}
        self.check(m_localRoutes, data, lambda o: [r["routeIpSubnet"] for r in o["routes"]], ["198.51.100.0/24"], "localRoutes.routes")

    def test_branch_nat_rule(self):
        from mappers import m_branchNatMapsConfig
        maps = {"map1": {"prio": {"10": {"dir": "outbound", "match": {"intf": "lan0"}, "set": {}}, "20": {"dir": "outbound", "match": "unexpected", "set": {}}}}}
        self.check(m_branchNatMapsConfig, {"deployment": DEP, "branch-nat-maps": maps}, lambda o: [r["priorityLevel"] for r in o["branchNatRules"]], [10], "branchNatMapsConfig")

    def test_bridge_group_and_link_aggregation(self):
        from mappers import m_bridgeGroups, m_linkAggregation
        bg = {"portlist": "lan1,lan2", "mtu": 1500, "admin": True, "comments": ""}
        self.check(m_bridgeGroups, {"bridge-groups": {"blan0": bg, "blan1": {"mtu": 1500}}}, lambda o: [x["bridgeGroup"] for x in o], ["blan0"], "bridgeGroups")
        lag = {"portlist": "lan0,lan1", "mtu": 1500, "mode": 4, "lacp_rate": "slow", "lacp_sys_prio": 65535, "comment": ""}
        self.check(m_linkAggregation, {"link-aggregation": {"blan0": lag, "blan1": {"mtu": 1500}}}, lambda o: [x["channelGroup"] for x in o["linkAggregationGroups"]], ["blan0"], "linkAggregation")

    def test_ospf_segment(self):
        from mappers import m_segmentOspfConfig
        dep = {"sysConfig": dict(DEP["sysConfig"], vrfs=[{"id": "0", "name": "Default"}, {"id": "1", "name": "corp"}, {"id": "2", "name": "guest"}]), "modeIfs": DEP["modeIfs"]}
        iface = {"area": "0.0.0.0", "cost": 1, "priority": 1, "adminStatus": True, "helloInterval": 10, "deadInterval": 40, "transmitDelay": 1, "retransmitInterval": 5,
                 "authType": "None", "authKey": "", "md5Key": 0, "md5Password": "", "comment": "", "bfdDesired": False}
        data = {"deployment": dep, "ospf-areas": {}, "ospf-system-all-vrfs": {"0": {"enable": True}, "1": {"enable": True}, "2": "unexpected"},
                "ospf-interfaces-all-vrfs": {"0": {"lan0": iface}, "1": {"lan0.71": iface}, "2": {"lan0.72": iface}}}
        self.check(m_segmentOspfConfig, data, lambda o: [e["segment"] for e in o], ["Default", "corp"], "segmentOspfConfig")

    def test_bgp_segment(self):
        from mappers import m_segmentBgpSystems
        dep = {"sysConfig": dict(DEP["sysConfig"], vrfs=[{"id": "0", "name": "Default"}, {"id": "1", "name": "corp"}, {"id": "2", "name": "guest"}]), "modeIfs": DEP["modeIfs"]}
        systems = {"0": {"enable": True, "asn": 65000}, "1": {"enable": True, "asn": 65000}, "2": {"enable": True}}
        self.check(m_segmentBgpSystems, {"deployment": dep, "bgp-system-all-vrfs": systems, "bgp-neighbors-all-vrfs": {}}, lambda o: [e["segment"] for e in o], ["Default", "corp"], "segmentBgpSystems")

    def test_bfd_segment(self):
        from mappers import m_segmentBfdConfigs
        bfd = {"0": {"enable": True, "minRxInterval": 300, "minTxInterval": 300, "detectMultiplier": 3}, "1": {"enable": True}}
        self.check(m_segmentBfdConfigs, {"deployment": DEP3, "bfd-vrfs": bfd}, lambda o: [e["segment"] for e in o], ["Default"], "segmentBfdConfigs")  # vrf 1 names a segment: its item is malformed, not unresolved

    def test_custom_tag(self):
        from mappers import m_customApplianceTags
        self.check(m_customApplianceTags, {"custom-tags": {"1": {"name": "site", "value": "a"}, "2": {"name": "region"}}}, lambda o: [t["key"] for t in o["customApplianceTagsInterfaces"]], ["site"], "customApplianceTags")

    def test_multicast_segment(self):
        from mappers import m_multicast
        good = {"vrf_id": 0, "rp": "192.0.2.9", "pim": {}, "igmp": {}, "filter_name": None}
        bad = {"vrf_id": 1, "pim": "unexpected"}
        data = {"deployment": DEP, "multicast-config": [good, bad], "multicast-enable": [{"vrf_id": 0, "enable": True}]}
        self.check(m_multicast, data, lambda o: [e["segment"] for e in o], ["Default"], "multicast")


DEP3 = {"sysConfig": dict(DEP["sysConfig"], vrfs=[{"id": "0", "name": "Default"}, {"id": "1", "name": "corp"}, {"id": "2", "name": "guest"}]),
        "modeIfs": [{"ifName": "lan0", "applianceIPs": [{"vlan": v, "label": "4"} for v in (0, 71, 72)]}, {"ifName": "lan1", "applianceIPs": [{"vlan": 0, "label": "4"}]}]}  # OSPF needs deployed interfaces
OSPF_IF = {"area": "0.0.0.0", "cost": 1, "priority": 1, "adminStatus": True, "helloInterval": 10, "deadInterval": 40, "transmitDelay": 1, "retransmitInterval": 5,
           "authType": "None", "authKey": "", "md5Key": 0, "md5Password": "", "comment": "", "bfdDesired": False}
NEIGHBOR = {"remote_as": 65001, "type": "Branch", "enable": True, "hold": 180, "ka": 60, "next_hop_self": False, "store_received_routes": True, "directly_connected": True}
ROUTE = {"configured": True, "local": True, "automatic": False, "prefix": "198.51.100.0/24", "nextHop": "192.0.2.254", "ifName": "lan0", "metric": 50, "advert": True, "advert_bgp": False, "advert_ospf": False}
VTI = {"ipaddr": "192.0.2.1", "nmask": 30, "admin": True, "tunnel": "pt1", "side": "lan", "label": "", "vrf_id": 0, "zone": 0, "auto_distribute": False, "behindNAT": "none"}
PF = {"srcSubnet": "0.0.0.0/0", "destSubnet": "192.0.2.10/32", "destPort": "443", "protocol": "tcp", "targetIp": "", "targetPort": "", "srcIf": "any", "vrf_id": 0, "comment": ""}
QUIET_DISPOSITIONS = QUIET


def errors(notes):
    return [n for n in notes if n["disposition"] == "toolkit-error"]


class NoEmptySection(unittest.TestCase):
    """When every item of a list section fails, the section is not written: an empty list replaces the target's items on apply."""

    def check_dropped(self, name, mapper, data):
        c, notes = ctx(data)
        try:
            out = mapper(c)
        except Exception as err:  # translate's section-level catch also leaves it unwritten
            out = "raised {}".format(err)
        self.assertIsNone(out, name)
        self.assertTrue(errors(notes), name + ": the failure is not ledgered")

    def test_every_list_mapper(self):
        from mappers import (m_customApplianceTags, m_inboundPortForwarding, m_ipSlaRule, m_linkAggregation, m_localRoutes, m_loopbackInterface, m_ospfSystemConfig,
                             m_segmentBfdConfigs, m_segmentLocalRoutes, m_virtualTunnelInterface, m_bridgeGroups)
        bad_route = {k: v for k, v in ROUTE.items() if k != "metric"}
        cases = [
            ("multicast", m_multicast, {"deployment": DEP, "multicast-config": [{"vrf_id": 1, "pim": "unexpected"}]}),
            ("multicast None", m_multicast, {"deployment": DEP, "multicast-config": [None]}),
            ("bgp neighbors", m_bgpSystemConfig, {"deployment": DEP, "bgp-system": {"enable": True, "asn": 65000}, "bgp-neighbors": {"192.0.2.2": {"type": "Branch"}, "192.0.2.3": None}}),
            ("segment bgp neighbors", m_segmentBgpSystems, {"deployment": DEP3, "bgp-system-all-vrfs": {"0": {"enable": False, "asn": 1}, "1": {"enable": True, "asn": 65000}},
                                                            "bgp-neighbors-all-vrfs": {"1": {"192.0.2.2": {"type": "Branch"}}}}),
            ("local routes", m_localRoutes, {"deployment": DEP, "subnets": {"subnets": {"entries": [{"state": bad_route}, None]}}}),
            ("segment routes", m_segmentLocalRoutes, {"deployment": DEP3, "subnets-all-vrfs": {"subnets": {"1": {"entries": [{"state": bad_route}]}}}}),
            ("vrrp", m_vrrp, {"vrrp": [None, {"groupId": 2}]}),
            ("loopbacks", m_loopbackInterface, {"deployment": DEP, "loopbacks": {"lo1": None, "lo2": {"admin": True}}}),
            ("lag", m_linkAggregation, {"link-aggregation": {"blan0": None, "blan1": {"mtu": 1500}}}),
            ("bridge", m_bridgeGroups, {"bridge-groups": {"blan0": None, "blan1": {"mtu": 1500}}}),
            ("bfd", m_segmentBfdConfigs, {"deployment": DEP, "bfd-vrfs": {"0": None, "1": {"enable": True}}}),
            ("tags", m_customApplianceTags, {"custom-tags": {"1": None, "x": {"name": "a", "value": "b"}}}),
            ("port forwarding", m_inboundPortForwarding, {"deployment": DEP, "port-forwarding": [None, {"srcIf": "any", "comment": ""}]}),
            ("ip sla", m_ipSlaRule, {"deployment": DEP, "ipsla-managers": {"MGR_1": None}}),
            ("branch nat", m_branchNatMapsConfig, {"deployment": DEP, "branch-nat-maps": {"map1": {"prio": {"10": None, "20": {"match": "x"}}}}}),
            ("vti", m_virtualTunnelInterface, {"deployment": DEP, "vtis": {"vti1": None, "vti2": {"ipaddr": "192.0.2.5"}}}),
            ("ospf system interfaces", m_ospfSystemConfig, {"deployment": DEP, "ospf-system": {"enable": True}, "ospf-areas": {}, "ospf-interfaces": {"lan0": None}}),
            ("segment ospf", m_segmentOspfConfig, {"deployment": DEP3, "ospf-areas": {}, "ospf-system-all-vrfs": {"1": None}, "ospf-interfaces-all-vrfs": {}}),
            ("segment ospf interfaces", m_segmentOspfConfig, {"deployment": DEP3, "ospf-areas": {}, "ospf-system-all-vrfs": {"1": {"enable": True}}, "ospf-interfaces-all-vrfs": {"1": {"lan0.71": None}}}),
        ]
        for name, mapper, data in cases:
            with self.subTest(name):
                self.check_dropped(name, mapper, data)


class NonDictItems(IsolationCheck, unittest.TestCase):
    """A null or non-dict item is skipped like any other unreadable item; the filters and ledger loops around it must not trip on it."""

    def test_bridge_and_lag_null(self):
        from mappers import m_bridgeGroups, m_linkAggregation
        bg = {"portlist": "lan1,lan2", "mtu": 1500, "admin": True, "comments": ""}
        self.check(m_bridgeGroups, {"bridge-groups": {"blan0": bg, "blan1": None}}, lambda o: [x["bridgeGroup"] for x in o], ["blan0"], "bridgeGroups")
        lag = {"portlist": "lan0,lan1", "mtu": 1500, "mode": 4, "lacp_rate": "slow", "lacp_sys_prio": 65535, "comment": ""}
        self.check(m_linkAggregation, {"link-aggregation": {"blan0": lag, "blan1": None}}, lambda o: [x["channelGroup"] for x in o["linkAggregationGroups"]], ["blan0"], "linkAggregation")

    def test_bfd_null(self):
        from mappers import m_segmentBfdConfigs
        good = {"enable": True, "minRxInterval": 300, "minTxInterval": 300, "detectMultiplier": 3}
        self.check(m_segmentBfdConfigs, {"deployment": DEP, "bfd-vrfs": {"0": good, "1": None}}, lambda o: [e["segment"] for e in o], ["Default"], "segmentBfdConfigs")

    def test_tags_null_and_non_numeric_key(self):
        from mappers import m_customApplianceTags
        self.check(m_customApplianceTags, {"custom-tags": {"1": {"name": "site", "value": "a"}, "2": None}}, lambda o: [t["key"] for t in o["customApplianceTagsInterfaces"]], ["site"], "customApplianceTags")
        self.check(m_customApplianceTags, {"custom-tags": {"1": {"name": "site", "value": "a"}, "x": {"name": "r", "value": "b"}}}, lambda o: [t["key"] for t in o["customApplianceTagsInterfaces"]], ["site"], "customApplianceTags")

    def test_segment_ospf_null_segment_and_interface(self):
        data = {"deployment": DEP3, "ospf-areas": {}, "ospf-system-all-vrfs": {"0": {"enable": True}, "1": {"enable": True}, "2": None},
                "ospf-interfaces-all-vrfs": {"0": {"lan0": OSPF_IF}, "1": {"lan0.71": OSPF_IF}}}
        self.check(m_segmentOspfConfig, data, lambda o: [e["segment"] for e in o], ["Default", "corp"], "segmentOspfConfig")

    def test_port_forwarding_and_vrrp_null(self):
        from mappers import m_inboundPortForwarding
        self.check(m_inboundPortForwarding, {"deployment": DEP, "port-forwarding": [PF, None]}, lambda o: len(o["portForwardingRules"]), 1, "inboundPortForwarding")
        g = {"groupId": 1, "interface": "lan0", "enable": "Up", "vipaddr": "192.0.2.1", "adv_timer": 1, "priority": 100, "version": 2, "preempt": True, "pkt_trace": False, "holddown": 10}
        self.check(m_vrrp, {"vrrp": [g, None]}, lambda o: [e["groupId"] for e in o["vrrpEntries"]], [1], "vrrp")


class PerItemLists(IsolationCheck, unittest.TestCase):
    """Lists that used to be built in one expression: one bad entry is skipped, the rest are written."""

    def test_vti(self):
        from mappers import m_virtualTunnelInterface
        bad = {k: v for k, v in VTI.items() if k != "auto_distribute"}
        self.check(m_virtualTunnelInterface, {"deployment": DEP, "vtis": {"vti1": VTI, "vti2": bad}}, lambda o: [v["interfaceId"] for v in o["vtis"]], ["vti1"], "virtualTunnelInterface")

    def test_ospf_system_interface(self):
        from mappers import m_ospfSystemConfig
        bad = {k: v for k, v in OSPF_IF.items() if k != "cost"}
        data = {"deployment": DEP3, "ospf-system": {"enable": True}, "ospf-areas": {}, "ospf-interfaces": {"lan0": OSPF_IF, "lan1": bad}}
        self.check(m_ospfSystemConfig, data, lambda o: [i["interfaceName"] for i in o["interfaces"]], ["lan0"], "ospfSystemConfig.interfaces")

    def test_segment_ospf_interface(self):
        bad = {k: v for k, v in OSPF_IF.items() if k != "cost"}
        data = {"deployment": DEP3, "ospf-areas": {}, "ospf-system-all-vrfs": {"1": {"enable": True}}, "ospf-interfaces-all-vrfs": {"1": {"lan0.71": OSPF_IF, "lan0.72": bad}}}
        self.check(m_segmentOspfConfig, data, lambda o: [(e["segment"], [i["interfaceName"] for i in e["interfaces"]]) for e in o], [("corp", ["lan0.71"])], "segmentOspfConfig.interfaces")


class LedgerAccuracy(unittest.TestCase):
    def test_port_forwarding_names_the_captured_index(self):
        from mappers import m_inboundPortForwarding
        c, notes = ctx({"deployment": DEP, "port-forwarding": [dict(PF, comment="HA rule"), PF, {"srcIf": "any", "comment": ""}]})
        m_inboundPortForwarding(c)
        self.assertEqual([n["item"] for n in errors(notes)], ["port-forwarding[2]"])

    def test_branch_nat_failures_in_two_maps_are_two_lines(self):
        c, notes = ctx({"deployment": DEP, "branch-nat-maps": {"map1": {"prio": {"10": {"match": "x"}}}, "map2": {"prio": {"10": {"match": "x"}}}}})
        m_branchNatMapsConfig(c)
        self.assertEqual(len(errors(notes)), 2)

    def test_segment_failures_ledgered_under_their_section(self):
        from mappers import m_segmentLocalRoutes
        bad_route = {k: v for k, v in dict(ROUTE, prefix="203.0.113.0/24").items() if k != "metric"}
        c, notes = ctx({"deployment": DEP3, "subnets-all-vrfs": {"subnets": {"1": {"entries": [{"state": ROUTE}, {"state": bad_route}]}}}})
        m_segmentLocalRoutes(c)
        self.assertEqual({n["target"] for n in errors(notes)}, {"segmentLocalRoutes.routes"})
        c, notes = ctx({"deployment": DEP3, "bgp-system-all-vrfs": {"1": {"enable": True, "asn": 65000}},
                        "bgp-neighbors-all-vrfs": {"1": {"192.0.2.1": NEIGHBOR, "192.0.2.2": {"type": "Branch"}}}})
        m_segmentBgpSystems(c)
        self.assertEqual({n["target"] for n in errors(notes)}, {"segmentBgpSystems.neighbors"})

    def test_no_contradicting_default_note_for_failed_items(self):
        from mappers import m_segmentBfdConfigs, m_customApplianceTags
        for mapper, data in ((m_segmentBfdConfigs, {"deployment": DEP, "bfd-vrfs": {"0": {"enable": True}}}),
                             (m_customApplianceTags, {"custom-tags": {"1": {"name": "site"}}}),
                             (m_segmentBgpSystems, {"deployment": DEP3, "bgp-system-all-vrfs": {"0": {"enable": True, "asn": 1}, "1": {"enable": True, "asn": 1}, "2": {"enable": True}}, "bgp-neighbors-all-vrfs": {}})):
            with self.subTest(mapper.__name__):
                c, notes = ctx(data)
                mapper(c)
                self.assertTrue(errors(notes))
                self.assertEqual([n["note"] for n in notes if n["disposition"] == "default-omitted"
                                  and re.search(r"disabled|no tag has a name|guest", n["note"])], [])

    def test_dormant_ospf_segment_with_settings_is_visible(self):
        data = {"deployment": DEP3, "ospf-areas": {}, "ospf-interfaces-all-vrfs": {"0": {"lan0": OSPF_IF}},
                "ospf-system-all-vrfs": {"0": {"enable": True}, "1": {"enable": False, "routerId": "10.0.0.1", "redistMapToOSPF": "map1"}, "2": {"enable": False, "routerId": "0.0.0.0", "redistMapToOSPF": ""}}}
        c, notes = ctx(data)
        m_segmentOspfConfig(c)
        lines = [n for n in notes if n["item"] == "ospf-system-all-vrfs[1]"]
        self.assertTrue(lines and all(n["disposition"] not in QUIET_DISPOSITIONS for n in lines), lines)
        self.assertEqual([n["disposition"] for n in notes if n["item"] == "ospf-system-all-vrfs[2]"], ["default-omitted"])



SHARING = {"add_local_lan": True, "add_local_wan": False, "add_local_metric": 50, "add_local_communities": False, "local_communities": "", "local_asn_filter": False, "rtmap_to_subshare": "map1"}


class SilentGaps(unittest.TestCase):
    """Source config the converter cannot carry is ledgered visibly, never dropped in silence or written as an empty list."""

    def test_vni_maps_without_vtep_are_ledgered(self):
        from mappers import m_vxlan
        c, notes = ctx({"deployment": DEP3, "vxlan": {"ERROR": "NOT_AVAILABLE"}, "vxlan-vni-map": {"0": {"vni": 10000, "zoneId": 0, "role": 0}, "1": {"vni": 10010, "zoneId": 0, "role": 0}}})
        self.assertIsNone(m_vxlan(c))
        visible = [n for n in notes if n["target"].startswith("vxlan") and n["disposition"] not in QUIET_DISPOSITIONS]
        self.assertEqual(len(visible), 1, notes)
        self.assertIn("Default 10000", visible[0]["note"])
        self.assertIn("corp 10010", visible[0]["note"])

    def test_no_vni_maps_no_vxlan_note(self):
        from mappers import m_vxlan
        c, notes = ctx({"deployment": DEP3, "vxlan": {"ERROR": "NOT_AVAILABLE"}, "vxlan-vni-map": {"0": {"vni": 4294967295, "zoneId": 0, "role": 0}}})
        self.assertIsNone(m_vxlan(c))
        self.assertEqual([n for n in notes if n["target"].startswith("vxlan")], [])

    def test_unreadable_segment_routes_read(self):
        from mappers import m_segmentLocalRoutes
        data = {"deployment": DEP3, "subnets": {"subnets": {"entries": [{"state": ROUTE}]}},
                "system-info": {"auto_subnet": {"vrf": {"0": SHARING, "1": SHARING}}}}
        c, notes = ctx(data)
        out = m_segmentLocalRoutes(c)
        self.assertEqual([(e["segment"], [r["routeIpSubnet"] for r in e["routes"]]) for e in out], [("Default", ["198.51.100.0/24"])])
        lines = [n for n in notes if n["disposition"] == "not-readable"]
        self.assertEqual(len(lines), 1, notes)
        self.assertIn("corp", lines[0]["note"])
        self.assertFalse([n for n in notes if n["disposition"] == "mapped" and n["item"] == "subnets-all-vrfs"])

    def test_unread_segment_routes_with_only_default_sharing(self):
        from mappers import m_localRoutes, m_segmentLocalRoutes
        data = {"deployment": DEP3, "subnets": {"subnets": {"entries": [{"state": ROUTE}]}}, "system-info": {"auto_subnet": {"vrf": {"0": SHARING}}}}
        c, notes = ctx(data)
        self.assertEqual([r["routeIpSubnet"] for r in m_localRoutes(c)["routes"]], ["198.51.100.0/24"])
        self.assertIsNone(m_segmentLocalRoutes(c))
        lines = [n for n in notes if n["disposition"] == "not-readable"]
        self.assertEqual(len(lines), 1, notes)
        self.assertIn("corp", lines[0]["note"])
        self.assertIn("guest", lines[0]["note"])
        self.assertFalse([n for n in notes if n["item"] == "subnets-all-vrfs" and n["disposition"] == "default-omitted"])

    def test_no_routes_read_at_all(self):
        from mappers import m_localRoutes, m_segmentLocalRoutes
        c, notes = ctx({"deployment": DEP, "system-info": {"auto_subnet": {"vrf": {"0": SHARING}}}})
        self.assertIsNone(m_localRoutes(c))
        self.assertEqual([n["target"] for n in notes if n["disposition"] == "not-readable"], ["localRoutes.routes"])
        c, notes = ctx({"deployment": DEP3, "system-info": {"auto_subnet": {"vrf": {"0": SHARING, "1": SHARING}}}})
        self.assertIsNone(m_segmentLocalRoutes(c))
        self.assertTrue([n for n in notes if n["disposition"] == "not-readable"])



class ReviewRoundTwo(unittest.TestCase):
    """Second independent review of the isolation change: null per-segment blocks, defaults read as settings, ledger accuracy."""

    def written_empty(self, out, key):
        return [e for e in (out or []) if isinstance(e, dict) and e.get(key) == []]

    def test_null_segment_blocks_are_unreadable_not_empty(self):
        from mappers import m_segmentLocalRoutes
        cases = [
            (m_segmentLocalRoutes, {"deployment": DEP3, "subnets-all-vrfs": {"subnets": {"0": {"entries": [{"state": ROUTE}]}, "1": None}},
                                    "system-info": {"auto_subnet": {"vrf": {"0": SHARING, "1": SHARING}}}}, "routes"),
            (m_segmentBgpSystems, {"deployment": DEP3, "bgp-system-all-vrfs": {"0": {"enable": True, "asn": 1}, "1": {"enable": True, "asn": 65000}},
                                   "bgp-neighbors-all-vrfs": {"0": {"192.0.2.1": NEIGHBOR}, "1": None}}, "neighbors"),
            (m_segmentOspfConfig, {"deployment": DEP3, "ospf-areas": {}, "ospf-system-all-vrfs": {"0": {"enable": True}, "1": {"enable": True}},
                                   "ospf-interfaces-all-vrfs": {"0": {"lan0": OSPF_IF}, "1": None}}, "interfaces"),
        ]
        for mapper, data, key in cases:
            with self.subTest(mapper.__name__):
                c, notes = ctx(data)
                out = mapper(c)
                self.assertEqual(self.written_empty(out, key), [], out)
                self.assertEqual([e["segment"] for e in out], ["Default"])
                self.assertTrue(errors(notes))

    def test_null_segment_bgp_system_with_neighbors(self):
        c, notes = ctx({"deployment": DEP3, "bgp-system-all-vrfs": {"0": {"enable": True, "asn": 1}, "1": None}, "bgp-neighbors-all-vrfs": {"1": {"192.0.2.1": NEIGHBOR}}})
        m_segmentBgpSystems(c)
        self.assertEqual([(n["item"], n["disposition"]) for n in notes if n["item"] == "bgp-system-all-vrfs[1]"], [("bgp-system-all-vrfs[1]", "not-readable")])
        self.assertFalse([n for n in notes if n["disposition"] == "default-omitted" and "0 non-default" in n["note"]])

    def test_default_ospf_values_are_not_kept_settings(self):
        data = {"deployment": DEP3, "ospf-areas": {}, "ospf-interfaces-all-vrfs": {"0": {"lan0": OSPF_IF}},
                "ospf-system-all-vrfs": {"0": {"enable": True}, "1": {"enable": False, "routerId": "10.0.0.1", "redistMapToOSPF": "default_rtmap_to_ospf"},
                                         "2": {"enable": False, "routerId": "10.0.0.1", "redistMapToOSPF": "guest_map"}}}
        c, notes = ctx(data)
        m_segmentOspfConfig(c)
        self.assertEqual([n["disposition"] for n in notes if n["item"] == "ospf-system-all-vrfs[1]"], ["default-omitted"])
        self.assertEqual([n["disposition"] for n in notes if n["item"] == "ospf-system-all-vrfs[2]"], ["outside-preconfig"])

    def test_no_contradicting_localroutes_note_when_both_reads_fail(self):
        from mappers import m_localRoutes
        c, notes = ctx({"deployment": DEP3, "system-info": {"auto_subnet": {"vrf": {"0": SHARING, "1": SHARING}}}})
        self.assertIsNone(m_localRoutes(c))
        self.assertFalse([n for n in notes if n["target"] == "localRoutes" and "written in segmentLocalRoutes" in n["note"]])

    def test_no_mapped_zero_note(self):
        from mappers import m_segmentLocalRoutes
        bad_route = {k: v for k, v in ROUTE.items() if k != "metric"}
        for mapper, data in ((m_segmentBgpSystems, {"deployment": DEP3, "bgp-system-all-vrfs": {"1": {"enable": True, "asn": 1}}, "bgp-neighbors-all-vrfs": {"1": {"192.0.2.2": {"type": "x"}}}}),
                             (m_segmentOspfConfig, {"deployment": DEP3, "ospf-areas": {}, "ospf-system-all-vrfs": {"1": None}, "ospf-interfaces-all-vrfs": {}}),
                             (m_segmentLocalRoutes, {"deployment": DEP3, "subnets-all-vrfs": {"subnets": {"1": {"entries": [{"state": bad_route}]}}}})):
            with self.subTest(mapper.__name__):
                c, notes = ctx(data)
                self.assertIsNone(mapper(c))
                self.assertFalse([n for n in notes if n["disposition"] == "mapped"])

    def test_disabled_segment_bgp_with_unreadable_neighbors(self):
        c, notes = ctx({"deployment": DEP3, "bgp-system-all-vrfs": {"0": {"enable": True, "asn": 1}, "1": {"enable": False, "asn": 1}}, "bgp-neighbors-all-vrfs": {"1": None}})
        m_segmentBgpSystems(c)
        self.assertEqual([n["item"] for n in errors(notes)], ["bgp-system-all-vrfs[1]"])

    def test_branch_nat_non_numeric_priority(self):
        maps = {"map1": {"prio": {"10": {"dir": "outbound", "match": {"intf": "lan0"}, "set": {}}, "x": {"dir": "outbound", "match": {}, "set": {}}}}}
        c, notes = ctx({"deployment": DEP, "branch-nat-maps": maps})
        out = m_branchNatMapsConfig(c)
        self.assertEqual([r["priorityLevel"] for r in out["branchNatRules"]], [10])
        self.assertEqual([n["item"] for n in errors(notes)], ["branch-nat-maps[map1] rule x"])

    def test_segment_route_notes_name_their_section(self):
        from mappers import m_segmentLocalRoutes
        unresolved = dict(ROUTE, prefix="203.0.113.0/24", nextHop="", ifName="")
        c, notes = ctx({"deployment": DEP3, "subnets-all-vrfs": {"subnets": {"1": {"entries": [{"state": ROUTE}, {"state": unresolved}]}}}})
        m_segmentLocalRoutes(c)
        self.assertEqual({n["target"] for n in notes if n["disposition"] == "unresolved"}, {"segmentLocalRoutes.routes"})

    def test_vni_maps_with_unreadable_running_config(self):
        from mappers import m_vxlan
        c, notes = ctx({"deployment": DEP3, "vxlan": {"ERROR": "NOT_AVAILABLE"}, "vxlan-vni-map": {"0": {"vni": 10000, "zoneId": 0, "role": 0}}})
        m_vxlan(c)
        self.assertEqual([n["disposition"] for n in notes if n["item"] == "vxlan-vni-map"], ["not-readable"])
        c, notes = ctx({"deployment": DEP3, "vxlan": {"ERROR": "NOT_AVAILABLE"}, "vxlan-vni-map": [{"vni": 10000}], "running-config": {"runningConfig": "system hostname x"}})
        m_vxlan(c)
        self.assertEqual([n["disposition"] for n in notes if n["item"] == "vxlan-vni-map"], ["unresolved"])

    def test_empty_multicast_list_kept(self):
        c, notes = ctx({"deployment": DEP, "multicast-config": []})
        self.assertEqual(m_multicast(c), [])



class ReviewRoundThree(unittest.TestCase):
    """Third independent review: reads that could not be done are never "nothing configured", and never an empty list."""

    def unreadable(self, notes, item):
        return [n for n in notes if n["item"].startswith(item) and n["disposition"] == "not-readable"]

    def test_disabled_ospf_segment_with_null_interfaces(self):
        data = {"deployment": DEP3, "ospf-areas": {}, "ospf-system-all-vrfs": {"0": {"enable": True}, "1": {"enable": True}, "2": {"enable": False}},
                "ospf-interfaces-all-vrfs": {"0": {"lan0": OSPF_IF}, "1": {"lan0.71": OSPF_IF}, "2": None}}
        c, notes = ctx(data)
        self.assertEqual([e["segment"] for e in m_segmentOspfConfig(c)], ["Default", "corp"])
        self.assertTrue([n for n in errors(notes) + self.unreadable(notes, "ospf") if n["item"] == "ospf-system-all-vrfs[2]"], notes)
        self.assertFalse([n for n in notes if n["item"] == "ospf-system-all-vrfs[2]" and n["disposition"] in ("default-omitted", "mapped")])

    def test_vni_maps_when_vxlan_says_no_vtep(self):
        from mappers import m_vxlan
        c, notes = ctx({"deployment": DEP3, "vxlan": {"port": 4789, "vtepIf": ""}, "vxlan-vni-map": {"1": {"vni": 100}}})
        m_vxlan(c)
        self.assertEqual([n["disposition"] for n in notes if n["item"] == "vxlan-vni-map"], ["outside-preconfig"])

    def test_non_string_ospf_map_on_disabled_segment(self):
        data = {"deployment": DEP3, "ospf-areas": {}, "ospf-system-all-vrfs": {"0": {"enable": True}, "1": {"enable": True}, "2": {"enable": False, "redistMapToOSPF": 5}},
                "ospf-interfaces-all-vrfs": {"0": {"lan0": OSPF_IF}, "1": {"lan0.71": OSPF_IF}}}
        c, notes = ctx(data)
        self.assertEqual([e["segment"] for e in m_segmentOspfConfig(c)], ["Default", "corp"])

    def test_digit_like_keys_fail_alone(self):
        from mappers import m_customApplianceTags
        c, notes = ctx({"custom-tags": {"1": {"name": "site", "value": "a"}, "²": {"name": "r", "value": "b"}}})
        self.assertEqual([t["key"] for t in m_customApplianceTags(c)["customApplianceTagsInterfaces"]], ["site"])
        maps = {"map1": {"prio": {"10": {"dir": "outbound", "match": {"intf": "lan0"}, "set": {}}, "²": {"dir": "outbound", "match": {}, "set": {}}}}}
        c, notes = ctx({"deployment": DEP, "branch-nat-maps": maps})
        self.assertEqual([r["priorityLevel"] for r in m_branchNatMapsConfig(c)["branchNatRules"]], [10])

    def test_branch_nat_all_failed_no_none_configured_note(self):
        c, notes = ctx({"deployment": DEP, "branch-nat-maps": {"map1": {"prio": {"x": {"match": {}}}}}})
        self.assertIsNone(m_branchNatMapsConfig(c))
        self.assertTrue(errors(notes))
        self.assertFalse([n for n in notes if n["disposition"] == "default-omitted" and n["target"] == "branchNatMapsConfig"])

    def test_routes_read_without_a_table(self):
        from mappers import m_localRoutes, m_segmentLocalRoutes
        for table in (None, "unexpected"):
            data = {"deployment": DEP3, "subnets-all-vrfs": {"subnets": table}, "subnets": {"subnets": {"entries": [{"state": ROUTE}]}},
                    "system-info": {"auto_subnet": {"vrf": {"0": SHARING, "1": SHARING}}}}
            c, notes = ctx(data)
            out = m_segmentLocalRoutes(c)
            self.assertEqual([(e["segment"], [r["routeIpSubnet"] for r in e["routes"]]) for e in out], [("Default", ["198.51.100.0/24"])])
            self.assertTrue(self.unreadable(notes, "subnets-all-vrfs"))
        c, notes = ctx({"deployment": DEP, "subnets": {"subnets": None}, "system-info": {"auto_subnet": {"vrf": {"0": SHARING}}}})
        self.assertIsNone(m_localRoutes(c))
        self.assertTrue(self.unreadable(notes, "subnets"))

    def test_unreadable_neighbor_and_interface_reads(self):
        from mappers import m_ospfSystemConfig
        cases = [
            (m_segmentBgpSystems, {"deployment": DEP3, "bgp-system-all-vrfs": {"0": {"enable": True, "asn": 1}, "1": {"enable": True, "asn": 2}}}, "neighbors"),
            (m_bgpSystemConfig, {"deployment": DEP, "bgp-system": {"enable": True, "asn": 1}}, "neighbors"),
            (m_segmentOspfConfig, {"deployment": DEP3, "ospf-areas": {}, "ospf-system-all-vrfs": {"0": {"enable": True}, "1": {"enable": True}}}, "interfaces"),
            (m_ospfSystemConfig, {"deployment": DEP, "ospf-system": {"enable": True}, "ospf-areas": {}}, "interfaces"),
        ]
        for mapper, data, key in cases:
            with self.subTest(mapper.__name__):
                c, notes = ctx(data)
                out = mapper(c)
                entries = out if isinstance(out, list) else [out] if out else []
                self.assertEqual([e for e in entries if e.get(key) == []], [], out)
                self.assertTrue([n for n in notes if n["disposition"] == "not-readable"], notes)

    def test_null_segment_bgp_settings(self):
        c, notes = ctx({"deployment": DEP3, "bgp-system-all-vrfs": {"0": {"enable": True, "asn": 1}, "1": None}, "bgp-neighbors-all-vrfs": {}})
        m_segmentBgpSystems(c)
        self.assertTrue(self.unreadable(notes, "bgp-system-all-vrfs[1]"), notes)
        self.assertFalse([n for n in notes if n["disposition"] == "default-omitted" and "corp" in n["note"]])

    def test_default_bgp_settings_unread_with_neighbors(self):
        c, notes = ctx({"deployment": DEP, "bgp-neighbors": {"192.0.2.1": NEIGHBOR}})
        self.assertIsNone(m_bgpSystemConfig(c))
        self.assertTrue(self.unreadable(notes, "bgp-system"), notes)


class RouteLabelsAndContact(unittest.TestCase):
    """Route labels are their own dictionary (/cn/rtlabels in the running-config), not interface labels; a CLI-only contact is ledgered."""
    RTLABELS = ("internal set modify - /cn/rtlabels/config/1 value uint32 1\n"
                "internal set modify - /cn/rtlabels/config/1/name value string Internet\n"
                "internal set modify - /cn/rtlabels/config/2/name value string \"Backup path\"\n")
    # interface labels reuse the same ids with other names: resolving a route label there writes a wrong value
    DEP = {"sysConfig": dict(DEP["sysConfig"], ifLabels={"lan": [{"id": "4", "name": "Voice"}], "wan": [{"id": "1", "name": "INET"}, {"id": "2", "name": "MPLS"}, {"id": "7", "name": "LTE"}]}),
           "modeIfs": DEP["modeIfs"]}
    ROUTE = {"configured": True, "local": True, "automatic": False, "prefix": "203.0.113.0/24", "nextHop": "192.0.2.1", "ifName": "lan0", "metric": 50, "advert": True,
             "advert_bgp": False, "advert_ospf": False, "zone_id": "65534", "label": "1"}

    def routes(self, label, rc):
        from mappers import m_localRoutes
        data = {"deployment": self.DEP, "subnets": {"subnets": {"entries": [{"state": dict(self.ROUTE, label=label)}]}}}
        if rc is not None:
            data["running-config"] = {"runningConfig": rc}
        c, notes = ctx(data)
        return m_localRoutes(c)["routes"][0]["routeLabel"], notes

    def test_route_label_comes_from_route_labels(self):
        self.assertEqual(self.routes("1", self.RTLABELS)[0], "Internet")
        self.assertEqual(self.routes("2", self.RTLABELS)[0], "Backup path")
        self.assertEqual(self.routes("0", self.RTLABELS)[0], None)

    def test_unknown_route_label_is_null_and_ledgered(self):
        for rc in (self.RTLABELS, None):  # id 7 is an interface label only; no running-config at all
            label, notes = self.routes("7", rc)
            self.assertIsNone(label)
            gaps = [n for n in notes if n["disposition"] == "unresolved" and n["target"] == "localRoutes.routes.routeLabel"]
            self.assertEqual(len(gaps), 1, notes)
            self.assertIn("203.0.113.0/24", gaps[0]["note"])
            self.assertIn("7", gaps[0]["note"])
            # the reason must say why: no stored running-config is not "a label the running-config does not name"
            self.assertIn("no stored running-config" if rc is None else "do not name", gaps[0]["note"])

    def test_ip_sla_route_label_comes_from_route_labels(self):
        from mappers import m_ipSlaRule
        op = {"type": "port-monitor", "port-name": "wan1"}
        rule = {"enable": True, "interval": "10", "comment": "", "routeLabelId": 2, "upAction": "def-alarm", "downAction": "alarm", "operation": {"OPR_1": op}}
        c, _ = ctx({"deployment": self.DEP, "ipsla-managers": {"MGR_1": rule}, "running-config": {"runningConfig": self.RTLABELS}})
        self.assertEqual(m_ipSlaRule(c)["ruleEntries"][0]["routeLabel"], "Backup path")
        c, notes = ctx({"deployment": self.DEP, "ipsla-managers": {"MGR_1": dict(rule, routeLabelId=7)}, "running-config": {"runningConfig": self.RTLABELS}})
        self.assertIsNone(m_ipSlaRule(c)["ruleEntries"][0]["routeLabel"])
        self.assertTrue([n for n in notes if n["disposition"] == "unresolved" and n["item"] == "ipsla-managers[MGR_1]" and "7" in n["note"]], notes)

    def _build(self, ledger, **extra):
        dep = dict(copy.deepcopy(DEP), modeIfs=[])
        data = dict({"appliance": {"hostName": "h1", "groupId": "1.Network", "site": "S1", "networkRole": "0"}, "deployment": dep}, **extra)
        cap = FakeCap(data)
        cap.folder = "fake"
        return build(cap, ledger)

    def test_cli_only_contact_is_ledgered_not_guessed(self):
        rc = {"runningConfig": 'system hostname h1\nsystem contact "Ann Example, ann@example.com"\n'}
        ledger = []
        info = self._build(ledger, **{"running-config": rc, "extra-info": {"contact": None}})["applianceInfo"]
        self.assertEqual(info["contact"], {})  # one free-text string; the format splits name, email and phoneNumber
        gaps = [e for e in ledger if e["target"] == "applianceInfo.contact"]
        self.assertEqual([e["disposition"] for e in gaps], ["unresolved"], ledger)
        self.assertIn("Ann Example, ann@example.com", gaps[0]["note"])
        ledger = []
        info = self._build(ledger, **{"running-config": rc, "extra-info": {"contact": {"name": "NOC", "email": "noc@example.com"}}})["applianceInfo"]
        self.assertEqual(info["contact"], {"name": "NOC", "email": "noc@example.com"})
        self.assertEqual([e for e in ledger if e["target"] == "applianceInfo.contact"], [])


def null_segments(value, path=""):
    """Paths where a written value holds segment: null."""
    if isinstance(value, dict):
        return [path + ".segment"] * (value.get("segment", "") is None) + [p for k, v in value.items() for p in null_segments(v, path + "." + k)]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in null_segments(v, "{}[{}]".format(path, i))]
    return []


class SegmentNeverNull(unittest.TestCase):
    """A vrf id that names no segment (a deleted segment) is never written as segment: null, which Orchestrator applies to the Default
    segment: the item is skipped and ledgered unresolved, naming the id."""
    BFD = {"enable": True, "minRxInterval": 300, "minTxInterval": 300, "detectMultiplier": 3}

    def unresolved(self, notes):
        self.assertEqual(errors(notes), [])
        self.assertTrue([n for n in notes if n["disposition"] == "unresolved" and "vrf id 45 names no segment" in n["note"]], notes)

    def test_bfd_in_a_deleted_segment(self):
        from mappers import m_segmentBfdConfigs
        c, notes = ctx({"deployment": DEP, "bfd-vrfs": {"0": self.BFD, "45": self.BFD}})
        self.assertEqual([e["segment"] for e in m_segmentBfdConfigs(c)], ["Default"])
        self.unresolved(notes)
        self.assertEqual([n["item"] for n in notes if n["disposition"] == "unresolved"], ["bfd-vrfs[45]"])
        c, notes = ctx({"deployment": DEP, "bfd-vrfs": {"0": dict(self.BFD, enable=False), "45": self.BFD}})
        self.assertIsNone(m_segmentBfdConfigs(c))
        self.unresolved(notes)
        self.assertFalse([n for n in notes if n["disposition"] == "default-omitted"], "BFD is enabled in vrf 45: 'disabled in every segment' would be false")

    def test_every_segment_field(self):
        from mappers import m_inboundPortForwarding, m_loopbackInterface, m_natPools, m_segmentLocalRoutes, m_virtualTunnelInterface
        pim = {"lan0": {"dr_priority": 1, "enable": True, "hello_interval": 30, "join_prune_interval": 30}}
        nat_rule = {"dir": "inbound", "match": {"segment": 45, "intf": "any", "proto": "any"}, "set": {"trans_dst": "192.0.2.9"}}
        cases = [
            ("loopbacks", m_loopbackInterface, {"deployment": DEP, "loopbacks": {"lo1": {"admin": True, "ipaddr": "192.0.2.1", "nmask": 32, "label": "", "vrf_id": 45, "zone": 0},
                                                                                "lo2": {"admin": True, "ipaddr": "192.0.2.2", "nmask": 32, "label": "", "vrf_id": 0, "zone": 0}}},
             lambda o: [x["interfaceId"] for x in o["loopbacks"]], ["lo2"]),
            ("port forwarding", m_inboundPortForwarding, {"deployment": DEP, "port-forwarding": [dict(PF, vrf_id=45), PF]}, lambda o: [x["segment"] for x in o["portForwardingRules"]], ["Default"]),
            ("segment bgp", m_segmentBgpSystems, {"deployment": DEP3, "bgp-system-all-vrfs": {"0": {"enable": True, "asn": 65000}, "1": {"enable": True, "asn": 65000}, "45": {"enable": True, "asn": 65000}},
                                                  "bgp-neighbors-all-vrfs": {}}, lambda o: [x.get("segment", "(none)") for x in o], ["Default", "corp"]),
            ("nat pools", m_natPools, {"deployment": DEP, "nat-pools": {"1": {"name": "p1", "segment": 45, "dir": "outbound", "subnet": "198.51.100.0/30", "pat": 1, "comment": ""}}}, lambda o: o, None),
            ("segment ospf", m_segmentOspfConfig, {"deployment": DEP3, "ospf-areas": {}, "ospf-system-all-vrfs": {"0": {"enable": True}, "1": {"enable": True}, "45": {"enable": True}},
                                                   "ospf-interfaces-all-vrfs": {"0": {"lan0": OSPF_IF}, "1": {"lan0.71": OSPF_IF}, "45": {"lan0.9": OSPF_IF}}}, lambda o: [x["segment"] for x in o], ["Default", "corp"]),
            ("segment routes", m_segmentLocalRoutes, {"deployment": DEP3, "subnets-all-vrfs": {"subnets": {"0": {"entries": [{"state": ROUTE}]}, "45": {"entries": [{"state": ROUTE}]}}}},
             lambda o: [x["segment"] for x in o], ["Default"]),
            ("multicast", m_multicast, {"deployment": DEP, "multicast-enable": [{"vrf_id": 0, "enable": True}],
                                        "multicast-config": [{"vrf_id": 0, "rp": "192.0.2.9", "pim": pim, "igmp": {}, "filter_name": None}, {"vrf_id": 45, "rp": "", "pim": {}, "igmp": {}, "filter_name": None}]},
             lambda o: [x["segment"] for x in o], ["Default"]),
            ("vxlan", m_vxlan, {"deployment": DEP, "vxlan": {"port": 4789, "vtepIf": "lo1"}, "vxlan-vni-map": {"0": {"vni": 1001, "zoneId": 0, "role": 0}, "45": {"vni": 1045, "zoneId": 0, "role": 0}}},
             lambda o: [x["vni"] for x in o["vniVrfMaps"]], [1001]),
            ("vti", m_virtualTunnelInterface, {"deployment": DEP, "vtis": {"vti1": dict(VTI, vrf_id=45), "vti2": VTI}}, lambda o: [x["interfaceId"] for x in o["vtis"]], ["vti2"]),
            ("branch nat", m_branchNatMapsConfig, {"deployment": DEP, "branch-nat-maps": {"map1": {"prio": {"10": nat_rule, "20": dict(nat_rule, match={"segment": 0})}}}},
             lambda o: [x["priorityLevel"] for x in o["branchNatRules"]], [20]),
        ]
        for name, mapper, data, pick, good in cases:
            with self.subTest(name):
                c, notes = ctx(data)
                out = mapper(c)
                self.assertEqual(null_segments(out), [])
                self.assertEqual(pick(out) if out is not None else None, good)
                self.unresolved(notes)


class DhcpRemotePoolOptions(unittest.TestCase):
    """Remote pool options: the API returns each option's value without its code; the code is the key of the stored backup's
    /cn/dhcpd/config/subnet/<pool>/dhcp_options/<code> line, so an option is written only when the backup names its code."""
    POOL = {"subnet": "192.168.8.0/24", "scopeName": "GUEST", "ipRange": [], "gatewayIp": "192.168.8.1", "dnsServers": [], "ntpServers": [], "netbiosNameServers": [],
            "netbiosNodeType": "B", "maxLeaseTime": 600, "defaultLeaseTime": 60, "options": [{"value": "255.255.255.255"}, {"value": "192.0.2.7"}]}
    CLI = ("internal set modify - /cn/dhcpd/config/subnet/192.168.8.0\\\\/24/dhcp_options/42 value uint8 42\n"
           "internal set modify - /cn/dhcpd/config/subnet/192.168.8.0\\\\/24/dhcp_options/42/value value string 192.0.2.7\n"
           "internal set modify - /cn/dhcpd/config/subnet/192.168.8.0\\\\/24/dhcp_options/1 value uint8 1\n"
           "internal set modify - /cn/dhcpd/config/subnet/192.168.8.0\\\\/24/dhcp_options/1/value value string 255.255.255.255\n"
           "internal set modify - /cn/dhcpd/config/subnet/10.9.9.0\\\\/24/dhcp_options/3/value value string 192.0.2.7\n")

    def test_codes_from_the_stored_backup(self):
        c, notes = ctx({"dhcp-remote-subnets": [self.POOL], "running-config": {"runningConfig": self.CLI}})
        self.assertEqual(m_dhcpRemoteAddressPoolConfig(c).get("options"), [{"option": 1, "value": "255.255.255.255"}, {"option": 42, "value": "192.0.2.7"}])
        self.assertFalse([n for n in notes if n["disposition"] in ("unresolved", "unmapped-source-key")], notes)

    def test_no_code_is_never_guessed(self):
        for name, rc in (("no backup", None), ("backup without the pool's options", {"runningConfig": self.CLI.replace("192.168.8.0", "10.8.8.0")}),
                         ("backup with other values", {"runningConfig": self.CLI.replace("192.0.2.7", "192.0.2.8")})):
            with self.subTest(name):
                c, notes = ctx({"dhcp-remote-subnets": [self.POOL], "running-config": rc})
                out = m_dhcpRemoteAddressPoolConfig(c)
                self.assertEqual(out["dhcpAddressMask"], "192.168.8.0/24")
                self.assertNotIn("options", out)
                gaps = [n["note"] for n in notes if n["disposition"] == "unresolved" and n["target"] == "dhcpRemoteAddressPoolConfig.options"]
                self.assertEqual(len(gaps), 2, notes)
                self.assertTrue("255.255.255.255" in gaps[0] and "192.0.2.7" in gaps[1], gaps)

    def test_the_written_pool_mixed_codes_and_spaces(self):
        cli = self.CLI + ("internal set modify - /cn/dhcpd/config/subnet/192.168.9.0\\\\/24/dhcp_options/15/value value string corp.example lab.example\n")
        first = dict(self.POOL, options=[{"option": 1, "value": "255.255.255.255"}, {"value": "192.0.2.7"}])
        second = dict(self.POOL, subnet="192.168.9.0/24", options=[{"value": "corp.example lab.example"}])
        c, _ = ctx({"dhcp-remote-subnets": [first], "running-config": {"runningConfig": cli}})
        self.assertEqual(m_dhcpRemoteAddressPoolConfig(c).get("options"), [{"option": 1, "value": "255.255.255.255"}, {"option": 42, "value": "192.0.2.7"}])
        c, _ = ctx({"dhcp-remote-subnets": [first, second], "running-config": {"runningConfig": cli}})
        self.assertEqual(m_dhcpRemoteAddressPoolConfig(c).get("options"), [{"option": 15, "value": "corp.example lab.example"}])  # the latest pool is the one written

    def test_a_malformed_option_keeps_the_pool(self):
        for bad in (None, "x", {"option": 3}, {"option": "router", "value": "192.0.2.1"}):
            with self.subTest(bad=bad):
                c, notes = ctx({"dhcp-remote-subnets": [dict(self.POOL, options=[self.POOL["options"][0], bad, self.POOL["options"][1]])], "running-config": {"runningConfig": self.CLI}})
                try:
                    out = m_dhcpRemoteAddressPoolConfig(c)
                except Exception as err:  # translate's section-level catch would drop the whole pool
                    out = "raised {!r}".format(err)
                self.assertEqual(out.get("options") if isinstance(out, dict) else out, [{"option": 1, "value": "255.255.255.255"}, {"option": 42, "value": "192.0.2.7"}])
                self.assertEqual([(n["item"], n["target"]) for n in notes if n["disposition"] == "toolkit-error"], [("dhcp-remote-subnets.options[1]", "dhcpRemoteAddressPoolConfig.options")])

    def test_options_of_another_shape_keep_the_pool(self):
        c, notes = ctx({"dhcp-remote-subnets": [dict(self.POOL, options={"1": "x", "42": "y"})]})
        self.assertEqual(m_dhcpRemoteAddressPoolConfig(c)["dhcpAddressMask"], "192.168.8.0/24")
        self.assertEqual([n["item"] for n in notes if n["disposition"] == "toolkit-error"], ["dhcp-remote-subnets.options[0]"])

    def test_an_option_with_its_code_is_written_as_is(self):
        c, notes = ctx({"dhcp-remote-subnets": [dict(self.POOL, options=[{"option": 6, "value": "192.0.2.53"}])]})
        self.assertEqual(m_dhcpRemoteAddressPoolConfig(c).get("options"), [{"option": 6, "value": "192.0.2.53"}])


class MulticastOneObject(unittest.TestCase):
    """ECOS before 9.7 returns multicast as one object without vrf_id (seen on 9.5.7 and 9.6.4): it is the Default segment's; named
    interfaces are written, the virtual PIM interfaces (pimN) are ledgered as runtime."""
    PIM = {"dr_priority": 1, "enable": True, "hello_interval": 30, "join_prune_interval": 30}

    def test_configured_object_is_the_default_segment(self):
        c, notes = ctx({"deployment": DEP, "multicast-enable": {"enable": True},
                        "multicast-config": {"rp": "192.0.2.9", "pim": {"lan0": self.PIM, "pim0": self.PIM, "pim1": self.PIM}, "igmp": {"lan0": {"enable": True}}, "filter_name": ""}})
        self.assertEqual(m_multicast(c), [{"segment": "Default", "enable": "true", "rpAddresses": "192.0.2.9", "filterName": None,
                                           "pim": [{"interfaceName": "lan0", "pimEnable": True, "igmpEnable": True, "drPriority": 1, "helloInterval": 30, "joinPruneInterval": 30}]}])
        self.assertEqual(sorted(n["note"].split("'")[1] for n in notes if n["disposition"] == "runtime"), ["pim0", "pim1"])
        self.assertTrue(all("virtual PIM interface" in n["note"] for n in notes if n["disposition"] == "runtime"), notes)
        self.assertFalse([n for n in notes if n["disposition"] in ("unresolved", "toolkit-error")], notes)

    def test_switched_off_but_configured_and_other_unknown_entries(self):
        c, notes = ctx({"deployment": DEP, "multicast-enable": {"enable": False}, "multicast-config": {"rp": "192.0.2.9", "pim": {"pimlan": self.PIM}, "igmp": {}, "filter_name": ""}})
        out = m_multicast(c)
        self.assertEqual((out[0]["enable"], out[0]["rpAddresses"], out[0]["pim"]), ("false", "192.0.2.9", []))
        self.assertEqual([n["note"] for n in notes if n["disposition"] == "runtime"], ["pim entry 'pimlan' matches no interface or label of this appliance (stale); the validator rejects it"])
        self.assertTrue([n for n in notes if n["disposition"] == "mapped" and "written as the Default segment (assumption" in n["note"]], notes)

    def test_unknown_enable_is_not_called_disabled(self):
        empty = {"rp": "", "pim": {}, "igmp": {}, "filter_name": ""}
        for enable in (None, "odd", {"enable": "maybe"}, {}):
            with self.subTest(enable=enable):
                c, notes = ctx({"deployment": DEP, "multicast-enable": enable, "multicast-config": empty})
                self.assertIsNone(m_multicast(c))
                self.assertEqual([(n["disposition"], n["target"]) for n in notes if n["item"].startswith("multicast")], [("not-readable", "multicast")])
        c, notes = ctx({"deployment": DEP, "multicast-config": dict(empty, rp="192.0.2.9")})
        self.assertEqual(m_multicast(c)[0]["enable"], "none")
        self.assertEqual([n["target"] for n in notes if n["disposition"] == "not-readable"], ["multicast.enable"])

    def test_unconfigured_object_is_default_omitted(self):
        c, notes = ctx({"deployment": DEP, "multicast-enable": {"enable": False}, "multicast-config": {"rp": "", "pim": {}, "igmp": {}, "filter_name": ""}})
        self.assertIsNone(m_multicast(c))
        self.assertEqual([n["disposition"] for n in notes if n["item"] == "multicast-config"], ["default-omitted"])
        c, notes = ctx({"deployment": DEP, "multicast-enable": {"enable": True}, "multicast-config": {"rp": "", "pim": {}, "igmp": {}, "filter_name": ""}})
        self.assertEqual(m_multicast(c)[0]["enable"], "true")  # switched on with nothing else set is still a setting


class ManagedBgpNeighbors(unittest.TestCase):
    """BGP neighbors Orchestrator services create (gms_marked) are skipped as before, and the ledger names them."""

    def test_skipped_neighbors_are_ledgered(self):
        neighbors = {"192.0.2.2": NEIGHBOR, "192.0.2.9": dict(NEIGHBOR, gms_marked=True)}
        c, notes = ctx({"deployment": DEP, "bgp-system": {"enable": True, "asn": 65000}, "bgp-neighbors": neighbors})
        self.assertEqual([n["peerIpAddress"] for n in m_bgpSystemConfig(c)["neighbors"]], ["192.0.2.2"])
        self.assertEqual([(n["item"], n["target"], "192.0.2.9" in n["note"]) for n in notes if n["disposition"] == "orchestrator-managed"],
                         [("bgp-system", "bgpSystemConfig.neighbors", True)])
        c, notes = ctx({"deployment": DEP3, "bgp-system-all-vrfs": {"0": {"enable": True, "asn": 65000}, "1": {"enable": True, "asn": 65000}},
                        "bgp-neighbors-all-vrfs": {"1": {"192.0.2.9": dict(NEIGHBOR, gmsMarked=True), "192.0.2.10": dict(NEIGHBOR, gms_marked=True)}}})
        self.assertEqual([s["neighbors"] for s in m_segmentBgpSystems(c)], [[], []])
        self.assertEqual([(n["item"], n["target"], "192.0.2.10, 192.0.2.9" in n["note"]) for n in notes if n["disposition"] == "orchestrator-managed"],
                         [("bgp-system-all-vrfs[1]", "segmentBgpSystems.neighbors", True)])


class DormantFlowRedirection(unittest.TestCase):
    def test_cluster_interface_without_peers_is_ledgered(self):
        c, notes = ctx({"running-config": {"fileName": "b", "backupTime": "1", "runningConfig": "cluster interface wan0\n"}})
        self.assertIsNone(m_flowRedirection(c))
        self.assertEqual([(n["disposition"], n["target"], n["note"]) for n in notes], [("default-omitted", "flowRedirection", "cluster interface wan0 without peers (dormant)")])
        c, notes = ctx({"running-config": {"fileName": "b", "backupTime": "1", "runningConfig": "system hostname h1\n"}})
        self.assertIsNone(m_flowRedirection(c))
        self.assertEqual(notes, [])


class ManagementPorts(unittest.TestCase):
    """interfaceConfig never carries mgmt ports (the management plane is off-limits); their state is ledgered, never claimed as default."""
    UP = {"admin": True, "ifSpeed": "auto", "ifDuplex": "auto"}

    def test_only_mgmt0_down_is_ledgered(self):
        info = [dict(self.UP, ifname="mgmt0"), dict(self.UP, ifname="mgmt1", admin=False), dict(self.UP, ifname="lan0")]
        c, notes = ctx({"interface-state": {"ifInfo": info}})
        self.assertIsNone(m_interfaceConfig(c))
        self.assertEqual([n["item"] for n in notes if n["disposition"] != "default-omitted"], [])  # mgmt1 down is the usual state
        c, notes = ctx({"interface-state": {"ifInfo": [dict(self.UP, ifname="mgmt0", ifSpeed="100", ifDuplex="full")]}})
        m_interfaceConfig(c)
        self.assertEqual([n["item"] for n in notes if n["disposition"] != "default-omitted"], [])  # mgmt0 up: speed and duplex are not ledgered

    def test_mgmt_admin_down_is_ledgered_not_carried(self):
        info = [dict(self.UP, ifname="mgmt0", admin=False), dict(self.UP, ifname="wan0"), dict(self.UP, ifname="lan0"), dict(self.UP, ifname="mgmt1")]
        c, notes = ctx({"interface-state": {"ifInfo": info}})
        self.assertIsNone(m_interfaceConfig(c))
        self.assertEqual([(n["disposition"], n["item"]) for n in notes if n["target"] == "interfaceConfig"],
                         [("outside-preconfig", "interface-state[mgmt0]"), ("default-omitted", "interface-state")])
        self.assertIn("admin down", [n for n in notes if n["item"] == "interface-state[mgmt0]"][0]["note"])
        self.assertNotIn("every physical interface", [n for n in notes if n["item"] == "interface-state"][0]["note"])
        c, notes = ctx({"interface-state": {"ifInfo": [dict(self.UP, ifname="mgmt0", admin=False), dict(self.UP, ifname="lan0", admin=False)]}})
        self.assertEqual(m_interfaceConfig(c)["interfaces"], [{"interfaceName": "lan0", "interfaceSpeed": "auto", "interfaceDuplex": "auto", "admin": "down"}])
        self.assertEqual([n["item"] for n in notes if n["disposition"] == "outside-preconfig"], ["interface-state[mgmt0]"])  # lan0 down is carried, not ledgered


DEPZ = {"sysConfig": dict(DEP["sysConfig"], vrfs=[{"id": "0", "name": "Default"}, {"id": "1", "name": "corp"}],
                         vrfZonesMap={"0": {"2": {"id": 2, "name": "Guest"}, "5": {"id": 5, "name": "DMZ"}}, "1": {"3": {"id": 3, "name": "Corp"}}}),
        "modeIfs": [{"ifName": "lan0", "applianceIPs": [{"vlan": 0, "label": "4", "vrf": 0, "zone": 2}]},
                    {"ifName": "lan1", "applianceIPs": [{"vlan": 0, "label": "4", "vrf": 0, "zone": 2}, {"vlan": 71, "label": "4", "vrf": 1, "zone": 3}]}]}


class InterfaceRouteNextHopZero(unittest.TestCase):
    """A route with next hop 0.0.0.0 or :: and an interface: the interface has no effect, and apply on ECOS 9.7.1 rejects it ("Interface cannot be
    specified when Next Hop is 0.0.0.0"). It is written without the interface for every source and target ECOS; its zone stays as the source has it
    (ECOS ignores a zone on a route without an interface) (docs/decisions/0016). guard-ok: the old 9.7 drop/keep tests are replaced by that owner decision."""
    IFROUTE = {"state": dict(ROUTE, prefix="10.14.32.0/21", nextHop="", ifName=""), "config": {"prefix": "10.14.32.0/21", "ifName": "lan1", "nextHop": "0.0.0.0", "zone_id": 65534}}
    ANY_IF = {"state": dict(ROUTE, prefix="10.15.0.0/16", nextHop="", ifName=""), "config": {"prefix": "10.15.0.0/16", "ifName": "default", "nextHop": "0.0.0.0"}}
    V6 = {"state": dict(ROUTE, prefix="2001:db8:1::/48", nextHop="", ifName=""), "config": {"prefix": "2001:db8:1::/48", "ifName": "lan1", "nextHop": "::"}}
    WRITTEN = [("10.14.32.0/21", "0.0.0.0", None, None), ("10.15.0.0/16", "0.0.0.0", None, None), ("198.51.100.0/24", "192.0.2.254", "lan0", None),
               ("2001:db8:1::/48", "::", None, None)]
    TAIL = "; the route's zone shows as none on the appliance, ECOS ignores a zone on a route without an interface (docs/decisions/0016)"
    STRIP = ["route 10.14.32.0/21 (segment Default): interface lan1 removed (next hop 0.0.0.0 with an interface has no effect; ECOS 9.7+ rejects it)" + TAIL,
             "route 2001:db8:1::/48 (segment Default): interface lan1 removed (next hop :: with an interface has no effect; ECOS 9.7+ rejects it)" + TAIL]

    def routes(self, ecos, entries=None, release="9.7.1.42046"):
        notes = []
        c = Ctx(FakeCap({"deployment": DEPZ, "subnets": {"subnets": {"entries": entries or [self.IFROUTE, self.ANY_IF, {"state": ROUTE}, self.V6]}}}), notes)
        c.target_release, c.target_ecos = release, ecos  # what translate --target-release and --target-ecos set
        from mappers import m_localRoutes
        return [(r["routeIpSubnet"], r["nextHop"], r["interfaceName"], r["zone"]) for r in m_localRoutes(c)["routes"]], notes

    @staticmethod
    def removed(notes):
        return [(n["disposition"], n["note"]) for n in notes if "removed (next hop" in n["note"]]

    def test_interface_is_removed_for_every_target_ecos(self):
        for ecos in ("9.6.2.1", "9.7.1.0", "10.0.0.1", None, "abc"):
            with self.subTest(ecos=ecos):
                routes, notes = self.routes(ecos)
                self.assertEqual(routes, self.WRITTEN)
                self.assertEqual(self.removed(notes), [("mapped", n) for n in self.STRIP])
                self.assertEqual([n for n in notes if n["disposition"] == "unresolved"], [])

    def test_the_zone_is_written_as_the_source_has_it(self):
        own = {"state": self.IFROUTE["state"], "config": dict(self.IFROUTE["config"], zone_id=5)}  # the interface's zone (Guest) is never taken
        routes, notes = self.routes("9.6.2.1", [own])
        self.assertEqual(routes, [("10.14.32.0/21", "0.0.0.0", None, "DMZ")])
        self.assertEqual(self.removed(notes), [("mapped", self.STRIP[0])])

    def test_merged_when_removing_the_interface_makes_two_routes_the_same(self):
        lan0 = {"state": self.IFROUTE["state"], "config": dict(self.IFROUTE["config"], ifName="lan0")}
        routes, notes = self.routes("9.6.2.1", [self.IFROUTE, lan0, {"state": ROUTE}])
        self.assertEqual(routes, [("10.14.32.0/21", "0.0.0.0", None, None), ("198.51.100.0/24", "192.0.2.254", "lan0", None)])
        self.assertEqual([(n["disposition"], n["note"]) for n in notes if "written once" in n["note"]],
                         [("mapped", "route 10.14.32.0/21 next hop 0.0.0.0, segment Default: two source routes are the same once the interface is removed; written once")])
        other = {"state": dict(self.IFROUTE["state"], metric=10), "config": dict(self.IFROUTE["config"], ifName="lan0")}
        routes, notes = self.routes("9.6.2.1", [self.IFROUTE, other])
        self.assertEqual(routes, [("10.14.32.0/21", "0.0.0.0", None, None)])
        self.assertEqual([n["note"] for n in notes if "written once" in n["note"]],
                         ["route 10.14.32.0/21 next hop 0.0.0.0, segment Default: two source routes are the same once the interface is removed; written once "
                          "with the first one's metric (assumption: confirm the merged route's settings)"])
        on_lan1 = {"state": dict(ROUTE, ifName="lan1")}  # a real next hop keeps its interface: not merged with the lan0 route
        routes, notes = self.routes("9.6.2.1", [{"state": ROUTE}, on_lan1])
        self.assertEqual(routes, [("198.51.100.0/24", "192.0.2.254", "lan0", None), ("198.51.100.0/24", "192.0.2.254", "lan1", None)])
        self.assertEqual([n for n in notes if "written once" in n["note"] or "removed (next hop" in n["note"]], [])

    def test_segment_route(self):
        from mappers import m_segmentLocalRoutes
        notes = []
        vlan = {"state": self.IFROUTE["state"], "config": dict(self.IFROUTE["config"], ifName="lan1.71")}
        c = Ctx(FakeCap({"deployment": DEPZ, "subnets-all-vrfs": {"subnets": {"1": {"entries": [vlan, {"state": ROUTE}]}}}}), notes)
        out = m_segmentLocalRoutes(c)
        self.assertEqual([(e["segment"], [(r["routeIpSubnet"], r["interfaceName"], r["zone"]) for r in e["routes"]]) for e in out],
                         [("corp", [("10.14.32.0/21", None, None), ("198.51.100.0/24", "lan0", None)])])
        self.assertEqual(self.removed(notes), [("mapped", "route 10.14.32.0/21 (segment corp): interface lan1.71 removed (next hop 0.0.0.0 with an interface has no effect; "
                                                           "ECOS 9.7+ rejects it)" + self.TAIL)])

    def test_translate_rejects_a_malformed_target_ecos(self):
        import contextlib, io, translate
        from unittest import mock
        seen = []
        with mock.patch.object(translate, "build", side_effect=lambda cap, ledger, target_ecos=None: seen.append(target_ecos) or (_ for _ in ()).throw(translate.NothingToConvert("stop"))), \
                mock.patch.object(translate, "Capture", side_effect=lambda folder: folder), contextlib.redirect_stderr(io.StringIO()) as err:
            for bad in ("abc", "", "latest", "9"):
                with self.assertRaises(SystemExit, msg=bad):
                    translate.main(["--capture", "x", "--site-type", "t", "--target-ecos", bad])
            translate.main(["--capture", "x", "--site-type", "t", "--target-ecos", "9.6.2.1_107093"])
        self.assertEqual(seen, ["9.6.2.1_107093"])
        self.assertIn("not an ECOS release", err.getvalue())

    def test_translate_passes_the_target_ecos(self):
        import contextlib, io, translate
        from unittest import mock
        seen = []

        def fake_build(cap, ledger, target_ecos=None):
            seen.append(target_ecos)
            raise translate.NothingToConvert("stop")
        with mock.patch.object(translate, "build", side_effect=fake_build), mock.patch.object(translate, "Capture", side_effect=lambda folder: folder), \
                contextlib.redirect_stderr(io.StringIO()):
            translate.main(["--capture", "x", "--site-type", "t", "--target-ecos", "9.6.2.1"])
            translate.main(["--capture", "x", "--site-type", "t"])
        self.assertEqual(seen, ["9.6.2.1", None])

    def test_build_writes_it_for_every_target_ecos(self):
        for ecos in ("9.6.2.1", "9.7.1.0", None):
            cap = FakeCap({"appliance": {"hostName": "h1", "groupId": "1.Network", "site": "S1", "networkRole": "0"}, "deployment": dict(copy.deepcopy(DEP), modeIfs=[]),
                           "subnets": {"subnets": {"entries": [self.IFROUTE]}}})
            cap.folder = "fake"
            ledger = []
            out = build(cap, ledger, target_ecos=ecos)
            self.assertEqual([(r["routeIpSubnet"], r["interfaceName"]) for r in out["localRoutes"]["routes"]], [("10.14.32.0/21", None)], ecos)
            self.assertEqual([e["disposition"] for e in ledger if "removed (next hop" in e["note"]], ["mapped"], ecos)


class InlineRouterOneSide(unittest.TestCase):
    """Apply rejects inline-router without both LAN and WAN interfaces ("Must provide both LAN side and WAN side interfaces for inline router
    mode"); /validate accepts it. The deployment is still written as the source has it, with a loud warning; the build never fails on it."""
    WAN = {"vlan": 0, "label": "1", "wanSide": True, "vrf": 0, "zone": 0, "harden": 1, "behindNAT": "none", "maxBW": {"outbound": 50000}, "version": 4, "ip": "198.51.100.10", "mask": 24, "wanNexthop": "198.51.100.1"}

    def build(self, mode_ifs, inline=True, ha_if=None):
        dep = copy.deepcopy(DEP)
        dep["sysConfig"].update(mode="router", inline=inline)
        if ha_if:
            dep["sysConfig"]["haIf"] = ha_if
        dep["sysConfig"]["ifLabels"]["wan"] = [{"id": "1", "name": "INET"}]
        dep["modeIfs"] = mode_ifs
        cap = FakeCap({"appliance": {"hostName": "h1", "groupId": "1.Network", "site": "S1", "networkRole": "0"}, "deployment": dep})
        cap.folder = "fake"
        ledger = []
        return build(cap, ledger), ledger

    def test_wan_only_router_is_written_and_warned(self):
        from translate import summary_md
        out, ledger = self.build([{"ifName": "wan0", "applianceIPs": [self.WAN]}])
        self.assertEqual((out["deploymentInfo"]["deploymentMode"], [i["interfaceName"] for i in out["deploymentInfo"]["deploymentInterfaces"]]), ("inline-router", ["wan0"]))
        gaps = [e for e in ledger if e["target"] == "deploymentInfo.deploymentMode"]
        self.assertEqual([(e["disposition"], e["note"]) for e in gaps],
                         [("unresolved", "inline-router with no LAN interface: the deployment step will be rejected on apply; set the deployment by hand")])
        summary = summary_md(ledger, out, {}, "9.7.1.42046")
        self.assertIn("**Warning: apply will fail**: inline-router with no LAN interface", summary.split("## ")[0])

    LAN = {"vlan": 0, "label": "4", "wanSide": False, "vrf": 0, "zone": 0, "ip": "192.0.2.1", "mask": 24}

    def warnings(self, *args, **kw):
        return [e["note"].split(":")[0] for e in self.build(*args, **kw)[1] if e["target"] == "deploymentInfo.deploymentMode"]

    def test_both_sides_no_warning(self):
        self.assertEqual(self.warnings([{"ifName": "wan0", "applianceIPs": [self.WAN]}, {"ifName": "lan0", "applianceIPs": [self.LAN]}]), [])

    def test_other_cases(self):
        lan0 = {"ifName": "lan0", "applianceIPs": [self.LAN]}
        self.assertEqual(self.warnings([lan0]), ["inline-router with no WAN interface"])
        self.assertEqual(self.warnings([{"ifName": "wan0", "applianceIPs": [self.WAN]}], inline=False), [])  # router mode, not inline-router
        self.assertEqual(self.warnings([{"ifName": "wan0", "applianceIPs": [self.WAN]}, {"ifName": "lan0", "applianceIPs": [{"vlan": 0}]}]), [])  # the LAN entry was unreadable
        self.assertEqual(self.warnings([lan0, {"ifName": "lan1", "applianceIPs": [dict(self.WAN, vlan=4000)]}], ha_if="lan1"), [])  # EdgeHA WAN links count


class OspfOnDeployedInterfaces(unittest.TestCase):
    """OSPF is written only on interfaces the preconfig deploys (deployment entries, user loopbacks and VTIs); an interface it does not
    create is ledgered, and an Orchestrator-managed loopback never gets OSPF."""
    LOOPBACKS = {"lo1": {"admin": True, "ipaddr": "192.0.2.1", "nmask": 32, "label": "", "vrf_id": 0, "zone": 0},
                 "lo20000": {"admin": True, "ipaddr": "192.0.2.2", "nmask": 32, "label": "", "vrf_id": 0, "zone": 0, "gms_marked": True}}

    def dropped(self, notes):
        return sorted((n["disposition"], n["note"].split(" is ")[0]) for n in notes if n["note"].startswith("OSPF interface"))

    def test_default_segment(self):
        c, notes = ctx({"deployment": DEP, "loopbacks": self.LOOPBACKS, "ospf-system": {"enable": True}, "ospf-areas": {},
                        "ospf-interfaces": {"lan0": OSPF_IF, "lan1": OSPF_IF, "lo1": OSPF_IF, "lo20000": OSPF_IF}})
        self.assertEqual([i["interfaceName"] for i in __import__("mappers").m_ospfSystemConfig(c)["interfaces"]], ["lan0", "lo1"])
        self.assertEqual(self.dropped(notes), [("orchestrator-managed", "OSPF interface lo20000"), ("unresolved", "OSPF interface lan1")])

    def test_segments(self):
        dep = copy.deepcopy(DEP3)
        dep["modeIfs"] = [{"ifName": "lan0", "applianceIPs": [{"vlan": 0, "label": "4"}, {"vlan": 71, "label": "4"}]}, {"ifName": "lan3", "applianceIPs": [{"vlan": 1, "label": "4"}]}]
        c, notes = ctx({"deployment": dep, "ospf-areas": {}, "ospf-system-all-vrfs": {"0": {"enable": True}, "1": {"enable": True}}, "vtis": {"vti1": VTI},
                        "ospf-interfaces-all-vrfs": {"0": {"lan0": OSPF_IF, "lan2": OSPF_IF, "vti1": OSPF_IF}, "1": {"lan0.71": OSPF_IF, "lan0.72": OSPF_IF, "lan3": OSPF_IF, "lan3.1": OSPF_IF}}})
        self.assertEqual([[i["interfaceName"] for i in s["interfaces"]] for s in m_segmentOspfConfig(c)], [["lan0", "vti1"], ["lan0.71", "lan3.1"]])
        self.assertEqual(self.dropped(notes), [("unresolved", "OSPF interface lan0.72"), ("unresolved", "OSPF interface lan2"), ("unresolved", "OSPF interface lan3")])


class InterfaceReferences(unittest.TestCase):
    """A field that names an interface the preconfig does not create is kept (the source's real value; the target may have the interface)
    and ledgered: orchestrator-managed for a gms_marked loopback or VTI, unresolved otherwise. The same check as the OSPF interfaces."""
    LOOPBACKS = {"lo20000": {"admin": True, "ipaddr": "192.0.2.2", "nmask": 32, "label": "", "vrf_id": 0, "zone": 0, "gms_marked": True}}

    def refs(self, notes):
        return sorted((n["disposition"], n["note"]) for n in notes if "references interface" in n["note"])

    def test_bgp_source_interfaces(self):
        neighbors = {"192.0.2.2": dict(NEIGHBOR, lcl_interface="lo20000"), "192.0.2.3": dict(NEIGHBOR, lcl_interface="lo20001"), "192.0.2.4": dict(NEIGHBOR, lcl_interface="lan0"),
                     "192.0.2.5": dict(NEIGHBOR, lcl_interface="any")}
        c, notes = ctx({"deployment": DEP, "loopbacks": self.LOOPBACKS, "bgp-system": {"enable": True, "asn": 65000}, "bgp-neighbors": neighbors})
        self.assertEqual([n["sourceIpInterface"] for n in m_bgpSystemConfig(c)["neighbors"]], ["lo20000", "lo20001", "lan0", "any"])  # kept as the source has them
        self.assertEqual(self.refs(notes), [
            ("orchestrator-managed", "BGP neighbor 192.0.2.2 references interface lo20000, an Orchestrator-managed interface (gms_marked); the target's Orchestrator must create it"),
            ("unresolved", "BGP neighbor 192.0.2.3 references interface lo20001, which this preconfig does not create; the target must already have it")])

    def test_vxlan_vrrp_route_and_ip_sla(self):
        c, notes = ctx({"deployment": DEP, "vxlan": {"port": 4789, "vtepIf": "lo20001"}, "vxlan-vni-map": {}})
        self.assertEqual(m_vxlan(c)["vtepSrcInterface"], "lo20001")
        self.assertEqual([d for d, _ in self.refs(notes)], ["unresolved"])
        group = {"groupId": 1, "interface": "lan0.9", "enable": "Up", "vipaddr": "192.0.2.1", "adv_timer": 1, "priority": 100, "version": 2, "preempt": True, "pkt_trace": False, "holddown": 10}
        c, notes = ctx({"deployment": DEP, "vrrp": [group, dict(group, groupId=2, interface="lan0")]})
        self.assertEqual([g["interfaceName"] for g in m_vrrp(c)["vrrpEntries"]], ["lan0.9", "lan0"])
        self.assertEqual(self.refs(notes), [("unresolved", "VRRP group 1 references interface lan0.9, which this preconfig does not create; the target must already have it")])
        from mappers import m_localRoutes
        c, notes = ctx({"deployment": DEP, "subnets": {"subnets": {"entries": [{"state": dict(ROUTE, ifName="lan7")}, {"state": dict(ROUTE, prefix="203.0.113.0/24")}]}}})
        self.assertEqual([r["interfaceName"] for r in m_localRoutes(c)["routes"]], ["lan7", "lan0"])
        self.assertEqual(self.refs(notes), [("unresolved", "route 198.51.100.0/24 references interface lan7, which this preconfig does not create; the target must already have it")])
        from mappers import m_ipSlaRule
        op = {"type": "ip-monitor", "ip-monitor-ip": "192.0.2.98", "tunnel-name": "to_peer", "src-port-name": "lo20000"}
        c, notes = ctx({"deployment": DEP, "loopbacks": self.LOOPBACKS, "ipsla-managers": {"MGR_1": {"enable": True, "interval": "1", "comment": "", "upAction": "def-alarm",
                                                                                                    "downAction": "alarm", "operation": {"OPR_1": op}}}})
        self.assertEqual(m_ipSlaRule(c)["ruleEntries"][0]["ipslaMonitor"]["sourceInterfaceName"], "lo20000")
        self.assertEqual([d for d, _ in self.refs(notes)], ["orchestrator-managed"])

    def test_segment_bgp_cli_vxlan_and_unreadable_interfaces(self):
        c, notes = ctx({"deployment": DEP3, "bgp-system-all-vrfs": {"0": {"enable": True, "asn": 65000}, "1": {"enable": True, "asn": 65000}},
                        "bgp-neighbors-all-vrfs": {"1": {"192.0.2.3": dict(NEIGHBOR, lcl_interface="lo20001")}}})
        m_segmentBgpSystems(c)
        self.assertEqual([n["item"] for n in notes if "references interface" in n["note"]], ["bgp-system-all-vrfs[1] neighbor 192.0.2.3"])  # not the "check" probe
        c, notes = ctx({"deployment": DEP, "running-config": {"runningConfig": "vxlan vtep-interface lo20001\n"}})
        self.assertEqual(m_vxlan(c)["vtepSrcInterface"], "lo20001")
        self.assertEqual([d for d, _ in self.refs(notes)], ["unresolved"])
        group = {"groupId": 1, "interface": "lan0.9", "enable": "Up", "vipaddr": "192.0.2.1", "adv_timer": 1, "priority": 100, "version": 2, "preempt": True, "pkt_trace": False, "holddown": 10}
        c, notes = ctx({"deployment": dict(DEP, modeIfs="odd"), "vrrp": [group]})
        self.assertEqual([g["interfaceName"] for g in m_vrrp(c)["vrrpEntries"]], ["lan0.9"])  # an unreadable interfaces read never stops the section
        self.assertEqual(self.refs(notes), [])

    def test_label_names_count_as_carried(self):
        from mappers import m_ipSlaRule
        op = {"type": "ip-monitor", "ip-monitor-ip": "192.0.2.98", "src-port-label": "Voice"}
        c, notes = ctx({"deployment": DEP, "ipsla-managers": {"MGR_1": {"enable": True, "interval": "1", "comment": "", "upAction": "def-alarm", "downAction": "alarm", "operation": {"OPR_1": op}}}})
        m_ipSlaRule(c)
        self.assertEqual(self.refs(notes), [])


if __name__ == "__main__":
    unittest.main()
