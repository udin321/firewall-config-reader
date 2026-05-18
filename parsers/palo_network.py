"""Palo Alto Network parser – full overhaul."""

from parsers.paloalto import PaloAltoParser, _members_el


def _tick(val) -> str:
    """Return ✓ for yes/true/enable/1, empty string otherwise."""
    return "✓" if str(val).lower() in ("yes", "true", "enable", "1") else ""


class PaloNetworkParser(PaloAltoParser):

    def _net(self):
        return self.dev.find("network") if self.dev else None

    def _build_zone_map(self):
        zm = {}
        if self.vsys is None:
            return zm
        for zone in self.vsys.findall("zone/entry"):
            zname = zone.get("name", "")
            net_el = zone.find("network")
            if net_el is not None:
                for t in [
                    "layer3",
                    "layer2",
                    "virtual-wire",
                    "tap",
                    "tunnel",
                    "external",
                ]:
                    for m in net_el.findall(f"{t}/member"):
                        if m.text:
                            zm[m.text] = zname
        return zm

    def _build_vr_map(self):
        vrm = {}
        net = self._net()
        if net is None:
            return vrm
        for vr in net.findall("virtual-router/entry"):
            vr_name = vr.get("name", "default")
            for m in vr.findall("interface/member"):
                if m.text:
                    vrm[m.text] = vr_name
        return vrm

    # ── INTERFACES ──────────────────────────────────────────────
    def get_ethernet_interfaces(self) -> list:
        net = self._net()
        if net is None:
            return []
        zone_map = self._build_zone_map()
        vr_map = self._build_vr_map()
        eth_el = net.find("interface/ethernet")
        rows = []
        if eth_el is not None:
            for e in eth_el.findall("entry"):
                name = e.get("name", "")
                if e.find("ha") is not None:
                    itype = "HA"
                    ag = "-"
                elif e.find("aggregate-group") is not None:
                    ag = e.findtext("aggregate-group", "-")
                    itype = f"Aggregate ({ag})"
                elif e.find("layer3") is not None:
                    itype = "Layer 3"
                    ag = "-"
                elif e.find("layer2") is not None:
                    itype = "Layer 2"
                    ag = "-"
                elif e.find("tap") is not None:
                    itype = "TAP"
                    ag = "-"
                elif e.find("virtual-wire") is not None:
                    itype = "Virtual Wire"
                    ag = "-"
                else:
                    itype = "Physical"
                    ag = "-"
                l3 = e.find("layer3")
                ips = [
                    x.get("name", "") for x in (l3.findall("ip/entry") if l3 else [])
                ]
                rows.append(
                    {
                        "Interface": name,
                        "Type": itype,
                        "Mgmt Profile": e.findtext("interface-management-profile", "-"),
                        "IP Address": ", ".join(ips) if ips else "none",
                        "Virtual Router": vr_map.get(name, "none"),
                        "Tag": e.findtext("tag", "-"),
                        "Zone": zone_map.get(name, "-"),
                        "Comment": e.findtext("comment", "-"),
                    }
                )
        # AE + sub-interfaces
        ae_el = net.find("interface/aggregate-ethernet")
        if ae_el is not None:
            for ae in ae_el.findall("entry"):
                name = ae.get("name", "")
                l3 = ae.find("layer3")
                ips = [
                    x.get("name", "") for x in (l3.findall("ip/entry") if l3 else [])
                ]
                rows.append(
                    {
                        "Interface": name,
                        "Type": "Aggregate (Parent)",
                        "Mgmt Profile": "-",
                        "IP Address": ", ".join(ips) if ips else "none",
                        "Virtual Router": vr_map.get(name, "none"),
                        "Tag": "-",
                        "Zone": zone_map.get(name, "-"),
                        "Comment": "-",
                    }
                )
                for u in (ae.findall("layer3/units/entry") if l3 else []):
                    uname = u.get("name", "")
                    u_ips = [x.get("name", "") for x in u.findall("ip/entry")]
                    rows.append(
                        {
                            "Interface": "  └ " + uname,
                            "Type": "Sub-Interface",
                            "Mgmt Profile": u.findtext(
                                "interface-management-profile", "-"
                            ),
                            "IP Address": ", ".join(u_ips) if u_ips else "none",
                            "Virtual Router": vr_map.get(uname, "none"),
                            "Tag": u.findtext("tag", "-"),
                            "Zone": zone_map.get(uname, "-"),
                            "SD-WAN Profile": u.findtext(
                                "sdwan-link-settings/sdwan-interface-profile", "-"
                            ),
                            "Upstream NAT": u.findtext(
                                "sdwan-link-settings/upstream-nat/enable", "no"
                            ),
                            "Comment": u.findtext("comment", "-"),
                        }
                    )
        return rows

    def get_vlan_interfaces(self) -> list:
        net = self._net()
        if net is None:
            return []
        zone_map = self._build_zone_map()
        vr_map = self._build_vr_map()
        vlan_units = net.find("interface/vlan/units")
        rows = []
        if vlan_units:
            for e in vlan_units.findall("entry"):
                name = e.get("name", "")
                ips = [x.get("name", "") for x in e.findall("ip/entry")]
                rows.append(
                    {
                        "Interface": name,
                        "Mgmt Profile": e.findtext("interface-management-profile", "-"),
                        "IP Address": ", ".join(ips) if ips else "-",
                        "Virtual Router": vr_map.get(name, "none"),
                        "Tag": e.findtext("tag", "-"),
                        "Zone": zone_map.get(name, "-"),
                        "SD-WAN Profile": e.findtext(
                            "sdwan-link-settings/sdwan-interface-profile", "-"
                        ),
                        "Comment": e.findtext("comment", "-"),
                    }
                )
        return rows

    def get_loopback_interfaces(self) -> list:
        net = self._net()
        if net is None:
            return []
        zone_map = self._build_zone_map()
        vr_map = self._build_vr_map()
        lo_units = net.find("interface/loopback/units")
        rows = []
        if lo_units:
            for e in lo_units.findall("entry"):
                name = e.get("name", "")
                ips = [x.get("name", "") for x in e.findall("ip/entry")]
                rows.append(
                    {
                        "Interface": name,
                        "Mgmt Profile": e.findtext("interface-management-profile", "-"),
                        "IP Address": ", ".join(ips) if ips else "-",
                        "Virtual Router": vr_map.get(name, "none"),
                        "Zone": zone_map.get(name, "-"),
                        "Comment": e.findtext("comment", "-"),
                    }
                )
        return rows

    def get_tunnel_interfaces(self) -> list:
        net = self._net()
        if net is None:
            return []
        zone_map = self._build_zone_map()
        vr_map = self._build_vr_map()
        tun_units = net.find("interface/tunnel/units")
        rows = []
        if tun_units:
            for e in tun_units.findall("entry"):
                name = e.get("name", "")
                ips = [x.get("name", "") for x in e.findall("ip/entry")]
                rows.append(
                    {
                        "Interface": name,
                        "Mgmt Profile": e.findtext("interface-management-profile", "-"),
                        "IP Address": ", ".join(ips) if ips else "-",
                        "Virtual Router": vr_map.get(name, "none"),
                        "Zone": zone_map.get(name, "-"),
                        "Comment": e.findtext("comment", "-"),
                    }
                )
        return rows

    def get_sdwan_interfaces(self) -> list:
        net = self._net()
        if net is None:
            return []
        zone_map = self._build_zone_map()
        vr_map = self._build_vr_map()
        sdwan_units = net.find("interface/sdwan/units")
        rows = []
        if sdwan_units:
            for e in sdwan_units.findall("entry"):
                name = e.get("name", "")
                members = [m.text for m in e.findall("interface/member") if m.text]
                rows.append(
                    {
                        "Interface": name,
                        "Virtual Router": vr_map.get(name, "none"),
                        "Zone": zone_map.get(name, "-"),
                        "Members": ", ".join(members) if members else "-",
                        "Comment": e.findtext("comment", "-"),
                    }
                )
        return rows

    # ── ZONES ───────────────────────────────────────────────────
    def get_zones(self) -> list:
        if self.vsys is None:
            return []
        rows = []
        for entry in self.vsys.findall("zone/entry"):
            net_el = entry.find("network")
            net_type, members = "-", []
            if net_el is not None:
                for t in [
                    "layer3",
                    "layer2",
                    "virtual-wire",
                    "tap",
                    "tunnel",
                    "external",
                ]:
                    el = net_el.find(t)
                    if el is not None:
                        members = [m.text for m in el.findall("member") if m.text]
                        net_type = t.replace("-", " ").title()
                        break
            uid_enabled = entry.findtext("enable-user-identification", "no")
            uid = entry.find("user-acl")
            rows.append(
                {
                    "Zone": entry.get("name", "-"),
                    "Type": net_type,
                    "Members": ", ".join(members) if members else "-",
                    "Zone Protection": entry.findtext("zone-protection-profile", "-"),
                    "User-ID Enabled": uid_enabled,
                    "User-ID Inc": _members_el(
                        uid.find("include-list") if uid else None, "-"
                    ),
                    "User-ID Exc": _members_el(
                        uid.find("exclude-list") if uid else None, "-"
                    ),
                    "Pkt Buffer Prot": entry.findtext(
                        "packet-buffer-protection/enable", "no"
                    ),
                }
            )
        return rows

    # ── VLANS ───────────────────────────────────────────────────
    def get_vlans(self) -> list:
        net = self._net()
        if net is None:
            return []
        vlan_el = net.find("vlan")
        if vlan_el is None:
            return []
        rows = []
        for e in vlan_el.findall("entry"):
            members = [m.text for m in e.findall("interface/member") if m.text]
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Interfaces": ", ".join(members) if members else "-",
                    "VLAN Intf": e.findtext("virtual-interface/interface", "-"),
                    "Static MAC": "-",
                }
            )
        return rows

    # ── VIRTUAL WIRES ───────────────────────────────────────────
    def get_virtual_wires(self) -> list:
        net = self._net()
        if net is None:
            return []
        vw_el = net.find("virtual-wire")
        if vw_el is None:
            return []
        rows = []
        for e in vw_el.findall("entry"):
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Interface 1": e.findtext("interface1", "-"),
                    "Interface 2": e.findtext("interface2", "-"),
                    "Tag Allowed": e.findtext("tag-allowed", "any"),
                    "Multicast": e.findtext("multicast-firewalling/enable", "no"),
                    "Link State": e.findtext("link-state-pass-through/enable", "no"),
                }
            )
        return rows

    # ── VIRTUAL ROUTER ──────────────────────────────────────────
    def get_virtual_routers(self) -> list:
        net = self._net()
        if net is None:
            return []
        rows = []
        for vr in net.findall("virtual-router/entry"):
            proto = vr.find("protocol")

            def _p(tag):
                el = proto.find(tag) if proto else None
                return el.findtext("enable", "no") if el else "no"

            intfs = [m.text for m in vr.findall("interface/member") if m.text]
            rows.append(
                {
                    "Name": vr.get("name", "default"),
                    "Interfaces": len(intfs),
                    "Static Routes": len(
                        vr.findall("routing-table/ip/static-route/entry")
                    ),
                    "RIP": _p("rip"),
                    "OSPF": _p("ospf"),
                    "OSPFv3": _p("ospfv3"),
                    "BGP": _p("bgp"),
                    "ECMP": "yes" if vr.find("ecmp") is not None else "no",
                    "_vr_el": vr,
                }
            )
        return rows

    def get_vr_detail(self, vr_el) -> dict:
        proto = vr_el.find("protocol")
        intfs = [m.text for m in vr_el.findall("interface/member") if m.text]
        ecmp = vr_el.find("ecmp")
        ecmp_info = {"enabled": "no"}
        if ecmp is not None:
            algo_el = ecmp.find("algorithm")
            method = "ip-modulo"
            if algo_el:
                for a in [
                    "ip-modulo",
                    "ip-hash",
                    "weighted-round-robin",
                    "balanced-round-robin",
                ]:
                    if algo_el.find(a) is not None:
                        method = a
                        break
            ecmp_info = {
                "enabled": "yes",
                "symmetric_return": ecmp.findtext("symmetric-return", "no"),
                "strict_source": ecmp.findtext("strict-source-path", "no"),
                "method": method,
            }

        ad = vr_el.find("admin-dists")
        ad_info = {}
        if ad:
            for k in [
                "static",
                "static-ipv6",
                "ospf-int",
                "ospf-ext",
                "ospfv3-int",
                "ospfv3-ext",
                "ibgp",
                "ebgp",
                "rip",
            ]:
                ad_info[k] = ad.findtext(k, "-")

        static_v4 = []
        for e in vr_el.findall("routing-table/ip/static-route/entry"):
            nh_ip = e.findtext("nexthop/ip-address", "")
            nh_vr = e.findtext("nexthop/next-vr", "")
            nh_dis = "discard" if e.find("nexthop/discard") is not None else ""
            nh_type = (
                "ip-address"
                if nh_ip
                else ("next-vr" if nh_vr else ("discard" if nh_dis else "none"))
            )
            nh_val = nh_ip or nh_vr or nh_dis or "-"
            rt = "unicast" if e.find("route-table/unicast") is not None else "-"
            pm = e.find("path-monitor")
            static_v4.append(
                {
                    "Name": e.get("name", "-"),
                    "Destination": e.findtext("destination", "-"),
                    "Interface": e.findtext("interface", "-"),
                    "NH Type": nh_type,
                    "NH Value": nh_val,
                    "Metric": e.findtext("metric", "-"),
                    "Route Table": rt,
                    "BFD": e.findtext("bfd/profile", "-"),
                    "Path Mon": (
                        "yes"
                        if (pm is not None and pm.findtext("enable", "no") == "yes")
                        else "no"
                    ),
                }
            )

        bgp = proto.find("bgp") if proto else None
        bgp_info = {}
        if bgp is not None:
            bgp_info = {
                "Enabled": bgp.findtext("enable", "no"),
                "Local AS": bgp.findtext("local-as", "-"),
                "Router ID": bgp.findtext("router-id", "-"),
                "Install Route": bgp.findtext("install-route", "no"),
                "Graceful Restart": bgp.findtext(
                    "routing-options/graceful-restart/enable", "no"
                ),
            }
        return {
            "name": vr_el.get("name", "default"),
            "interfaces": intfs,
            "ecmp": ecmp_info,
            "ad": ad_info,
            "static_v4": static_v4,
            "bgp": bgp_info,
        }

    # ── IPSEC / IKE ─────────────────────────────────────────────
    def get_ipsec_tunnels(self) -> list:
        net = self._net()
        if net is None:
            return []
        ike_gws = {}
        gw_el = net.find("ike/gateway")
        if gw_el:
            for e in gw_el.findall("entry"):
                ike_gws[e.get("name", "")] = {
                    "interface": e.findtext("local-address/interface", "-"),
                    "local_ip": e.findtext("local-address/ip", "-"),
                    "peer_ip": e.findtext("peer-address/ip", "-"),
                }
        zone_map = self._build_zone_map()
        vr_map = self._build_vr_map()
        rows = []
        ipsec_el = net.find("ipsec")
        if ipsec_el:
            for e in ipsec_el.findall("entry"):
                tun = e.findtext("tunnel-interface", "-")
                gw_name = ""
                for gwe in e.findall("auto-key/ike-gateway/entry"):
                    gw_name = gwe.get("name", "")
                    break
                gw = ike_gws.get(gw_name, {})
                rows.append(
                    {
                        "Name": e.get("name", "-"),
                        "Type": "IPSec",
                        "IKE GW": gw_name,
                        "IKE Interface": gw.get("interface", "-"),
                        "IKE Local IP": gw.get("local_ip", "-"),
                        "IKE Peer IP": gw.get("peer_ip", "-"),
                        "Tunnel Intf": tun,
                        "VR": vr_map.get(tun, "-"),
                        "Zone": zone_map.get(tun, "-"),
                        "Crypto": e.findtext("auto-key/ipsec-crypto-profile", "-"),
                        "Comment": e.findtext("comment", "-"),
                    }
                )
        return rows

    def get_ike_gateways(self) -> list:
        net = self._net()
        if net is None:
            return []
        gw_el = net.find("ike/gateway")
        if gw_el is None:
            return []
        rows = []
        for e in gw_el.findall("entry"):
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Peer Address": e.findtext("peer-address/ip", "-"),
                    "Local Intf": e.findtext("local-address/interface", "-"),
                    "Local IP": e.findtext("local-address/ip", "-"),
                    "Version": e.findtext("protocol/version", "ikev2"),
                    "Crypto Profile": (
                        e.findtext("protocol/ikev2/ike-crypto-profile")
                        or e.findtext("protocol/ikev1/ike-crypto-profile")
                        or "-"
                    ),
                    "NAT Traversal": e.findtext(
                        "protocol-common/nat-traversal/enable", "no"
                    ),
                    "Auth Method": (
                        "PSK"
                        if e.find("authentication/pre-shared-key") is not None
                        else "Cert"
                    ),
                }
            )
        return rows

    # ── DHCP ────────────────────────────────────────────────────
    def get_dhcp_servers(self) -> list:
        net = self._net()
        if net is None:
            return []
        dhcp = net.find("dhcp/interface")
        if dhcp is None:
            return []
        rows = []
        for e in dhcp.findall("entry"):
            server = e.find("server")
            if server is None:
                continue
            opt = server.find("option")
            lease_el = opt.find("lease") if opt else None
            lease = (
                "unlimited"
                if (lease_el is not None and lease_el.find("unlimited") is not None)
                else (lease_el.findtext("timeout", "-") if lease_el else "-")
            )
            pools = [m.text for m in server.findall("ip-pool/member") if m.text]
            rows.append(
                {
                    "Interface": e.get("name", "-"),
                    "Mode": server.findtext("mode", "auto"),
                    "Gateway": opt.findtext("gateway", "-") if opt else "-",
                    "Subnet Mask": opt.findtext("subnet-mask", "-") if opt else "-",
                    "Lease": lease,
                    "DNS Primary": opt.findtext("dns/primary", "-") if opt else "-",
                    "DNS Secondary": opt.findtext("dns/secondary", "-") if opt else "-",
                    "IP Pools": ", ".join(pools) if pools else "-",
                }
            )
        return rows

    def get_dhcp_relays(self) -> list:
        net = self._net()
        if net is None:
            return []
        dhcp = net.find("dhcp/interface")
        if dhcp is None:
            return []
        rows = []
        for e in dhcp.findall("entry"):
            relay = e.find("relay")
            if relay is None:
                continue
            v4_svrs = [x.get("name", "") for x in relay.findall("ip/server/entry")]
            v6_svrs = [x.get("name", "") for x in relay.findall("ipv6/server/entry")]
            rows.append(
                {
                    "Interface": e.get("name", "-"),
                    "IPv4 Enabled": relay.findtext("ip/enabled", "no"),
                    "IPv4 Servers": ", ".join(v4_svrs) if v4_svrs else "-",
                    "IPv6 Enabled": relay.findtext("ipv6/enabled", "no"),
                    "IPv6 Servers": ", ".join(v6_svrs) if v6_svrs else "-",
                }
            )
        return rows

    # ── DNS PROXY ───────────────────────────────────────────────
    def get_dns_proxies(self) -> list:
        net = self._net()
        if net is None:
            return []
        dp_el = net.find("dns-proxy")
        if dp_el is None:
            return []
        rows = []
        for e in dp_el.findall("entry"):
            intfs = [m.text for m in e.findall("interface/member") if m.text]
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Enabled": e.findtext("enabled", "yes"),
                    "Interfaces": ", ".join(intfs) if intfs else "-",
                    "Primary DNS": e.findtext("primary", "-"),
                    "Secondary DNS": e.findtext("secondary", "-"),
                    "Cache": e.findtext("caching/enable", "no"),
                    "Static Entries": len(e.findall("static-entries/entry")),
                }
            )
        return rows

    # ── GLOBALPROTECT ───────────────────────────────────────────
    def get_gp_portals(self) -> list:
        gp = self.vsys.find("global-protect") if self.vsys else None
        if gp is None:
            return []
        rows = []
        for e in gp.findall("global-protect-portal/entry"):
            pc = e.find("portal-config")
            auth_profile = "-"
            for ca in e.findall("portal-config/client-auth/entry"):
                auth_profile = ca.findtext("authentication-profile", "-")
                break
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Interface": (
                        pc.findtext("local-address/interface", "-") if pc else "-"
                    ),
                    "IP": pc.findtext("local-address/ip/ipv4", "-") if pc else "-",
                    "SSL Profile": (
                        pc.findtext("ssl-tls-service-profile", "-") if pc else "-"
                    ),
                    "Auth Profile": auth_profile,
                }
            )
        return rows

    def get_gp_gateways(self) -> list:
        gp = self.vsys.find("global-protect") if self.vsys else None
        if gp is None:
            return []
        rows = []
        for e in gp.findall("global-protect-gateway/entry"):
            la = e.find("local-address")
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Interface": la.findtext("interface", "-") if la else "-",
                    "Local IP": la.findtext("ip/ipv4", "-") if la else "-",
                    "Tunnel": e.findtext("remote-user-tunnel", "-"),
                    "SSL Profile": e.findtext("ssl-tls-service-profile", "-"),
                    "Tunnel Mode": e.findtext("tunnel-mode", "no"),
                }
            )
        return rows

    def get_gp_clientless_apps(self) -> list:
        gp = self.vsys.find("global-protect") if self.vsys else None
        if gp is None:
            return []
        rows = []
        for portal in gp.findall("global-protect-portal/entry"):
            pname = portal.get("name", "")
            for app in portal.findall(".//clientless-vpn/application/entry"):
                rows.append(
                    {
                        "Portal": pname,
                        "Name": app.get("name", "-"),
                        "URL": app.findtext("url", "-"),
                        "Desc": app.findtext("description", "-"),
                    }
                )
        return rows

    def get_gp_clientless_groups(self) -> list:
        gp = self.vsys.find("global-protect") if self.vsys else None
        if gp is None:
            return []
        rows = []
        for portal in gp.findall("global-protect-portal/entry"):
            pname = portal.get("name", "")
            for grp in portal.findall(".//clientless-vpn/app-group/entry"):
                rows.append(
                    {
                        "Portal": pname,
                        "Name": grp.get("name", "-"),
                        "Apps": _members_el(grp),
                    }
                )
        return rows

    # ── QOS ─────────────────────────────────────────────────────
    def get_qos_interfaces(self) -> list:
        net = self._net()
        if net is None:
            return []
        qos_intf = net.find("qos/interface")
        if qos_intf is None:
            return []
        rows = []
        for e in qos_intf.findall("entry"):
            rows.append(
                {
                    "Interface": e.get("name", "-"),
                    "Enabled": e.findtext("enabled", "no"),
                    "Clear Text Prof": e.findtext(
                        "regular-traffic/default-group/qos-profile", "-"
                    ),
                    "Tunnel Profile": e.findtext(
                        "tunnel-traffic/default-group/per-tunnel-qos-profile", "-"
                    ),
                }
            )
        return rows

    def get_qos_profiles(self) -> list:
        net = self._net()
        if net is None:
            return []
        qos_prof = net.find("qos/profile")
        if qos_prof is None:
            return []
        rows = []
        for e in qos_prof.findall("entry"):
            classes = []
            for ce in e.findall(".//class/entry"):
                classes.append(
                    {
                        "Class": ce.get("name", "-"),
                        "Priority": ce.findtext("priority", "-"),
                        "Max Egress": ce.findtext("class-bandwidth/egress-max", "0"),
                        "Guar Egress": ce.findtext(
                            "class-bandwidth/egress-guaranteed", "0"
                        ),
                    }
                )
            rows.append({"name": e.get("name", "-"), "classes": classes})
        return rows

    # ── NETWORK PROFILES ────────────────────────────────────────
    def get_ike_crypto_profiles(self) -> list:
        ike = self._net().find("ike") if self._net() else None
        if ike is None:
            return []
        el = ike.find("crypto-profiles/ike-crypto-profiles")
        if el is None:
            return []
        rows = []
        for e in el.findall("entry"):
            lt_el = e.find("lifetime")
            lt = "-"
            if lt_el:
                for u in ["hours", "minutes", "seconds", "days"]:
                    v = lt_el.findtext(u)
                    if v:
                        lt = f"{v} {u}"
                        break
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Encryption": _members_el(e.find("encryption")),
                    "Authentication": _members_el(e.find("hash")),
                    "DH Group": _members_el(e.find("dh-group")),
                    "Key Lifetime": lt,
                }
            )
        return rows

    def get_ipsec_crypto_profiles(self) -> list:
        ike = self._net().find("ike") if self._net() else None
        if ike is None:
            return []
        el = ike.find("crypto-profiles/ipsec-crypto-profiles")
        if el is None:
            return []
        rows = []
        for e in el.findall("entry"):
            esp = e.find("esp")
            ah = e.find("ah")
            lt_el = e.find("lifetime")
            lt = "-"
            if lt_el:
                for u in ["hours", "minutes", "seconds", "days"]:
                    v = lt_el.findtext(u)
                    if v:
                        lt = f"{v} {u}"
                        break
            if esp is not None:
                enc = _members_el(esp.find("encryption"))
                auth = _members_el(esp.find("authentication"))
                ptype = "ESP"
            elif ah is not None:
                enc = "-"
                auth = _members_el(ah.find("authentication"))
                ptype = "AH"
            else:
                enc = auth = ptype = "-"
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Type": ptype,
                    "Encryption": enc,
                    "Authentication": auth,
                    "DH Group": e.findtext("dh-group", "-"),
                    "Lifetime": lt,
                }
            )
        return rows

    def get_monitor_profiles(self) -> list:
        net = self._net()
        if net is None:
            return []
        el = net.find("profiles/monitor-profile")
        if el is None:
            return []
        rows = []
        for e in el.findall("entry"):
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Action": e.findtext("action", "wait"),
                    "Interval": e.findtext("interval", "3"),
                    "Threshold": e.findtext("threshold", "5"),
                }
            )
        return rows

    def get_intf_mgmt_profiles(self) -> list:
        net = self._net()
        if net is None:
            return []
        el = net.find("profiles/interface-management-profile")
        if el is None:
            return []

        def _chk(entry, tag):
            return "✓" if entry.findtext(tag, "no").lower() == "yes" else ""

        rows = []
        for e in el.findall("entry"):
            permitted = [m.text for m in e.findall("permitted-ip/entry")]
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Ping": _chk(e, "ping"),
                    "Telnet": _chk(e, "telnet"),
                    "SSH": _chk(e, "ssh"),
                    "HTTP": _chk(e, "http"),
                    "HTTPS": _chk(e, "https"),
                    "SNMP": _chk(e, "snmp"),
                    "Response Page": _chk(e, "response-pages"),
                    "User-ID": _chk(e, "userid-service"),
                    "Permitted IPs": (
                        ", ".join([p for p in permitted if p]) if permitted else "any"
                    ),
                }
            )
        return rows

    # ── SDWAN INTERFACE PROFILES ────────────────────────────────
    def get_sdwan_interface_profiles(self) -> list:
        el = self.vsys.find("sdwan-interface-profile") if self.vsys else None
        if el is None:
            return []
        rows = []
        for e in el.findall("entry"):
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Link Tag": e.findtext("link-tag", "-"),
                    "Link Type": e.findtext("link-type", "-"),
                    "Max Download": e.findtext("max-download", "-"),
                    "Max Upload": e.findtext("max-upload", "-"),
                    "Error Correct": e.findtext("error-correction", "no"),
                    "VPN Tunnel": e.findtext("vpn-data-tunnel-support", "no"),
                    "Path Monitor": e.findtext("path-monitoring", "Aggressive"),
                    "Probe Freq": e.findtext("probe-frequency", "-"),
                    "Probe Idle": e.findtext("probe-idle-time", "-"),
                    "Fallback Hold": e.findtext("failback-hold-time", "-"),
                    "Description": e.findtext("description", "-"),
                }
            )
        return rows

    def get_gre_tunnels(self) -> list:
        net = self._net()
        if net is None:
            return []
        gre_el = net.find("tunnel/gre")
        if gre_el is None:
            return []
        zone_map = self._build_zone_map()
        vr_map = self._build_vr_map()
        rows = []
        for e in gre_el.findall("entry"):
            tun = e.findtext("tunnel-interface", "-")
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Src Interface": e.findtext("local-address/interface", "-"),
                    "Local IP": e.findtext("local-address/ip", "-"),
                    "Peer IP": e.findtext("peer-address", "-"),
                    "Tunnel Intf": tun,
                    "VR": vr_map.get(tun, "-"),
                    "Zone": zone_map.get(tun, "-"),
                    "TTL": e.findtext("ttl", "-"),
                    "Keep Alive": _tick(e.findtext("keep-alive/enable", "no")),
                }
            )
        return rows

    def get_gp_mdm(self) -> list:
        gp = self.vsys.find("global-protect") if self.vsys else None
        if gp is None:
            return []
        rows = []
        for portal in gp.findall("global-protect-portal/entry"):
            pname = portal.get("name", "")
            for cfg in portal.findall(".//configs/entry"):
                mdm = cfg.find("mdm")
                if mdm is not None:
                    rows.append(
                        {
                            "Portal": pname,
                            "Config": cfg.get("name", "-"),
                            "Server": mdm.findtext("server-address", "-"),
                            "MDM Vendor": mdm.findtext("mdm-vendor", "-"),
                            "Client Cert": mdm.findtext(
                                "client-certificate-store", "-"
                            ),
                            "Status": "-",
                        }
                    )
        return rows

    def get_gp_ipsec_crypto(self) -> list:
        net = self._net()
        if net is None:
            return []
        el = net.find("ike/crypto-profiles/global-protect-ipsec-crypto-profiles")
        if el is None:
            return []
        rows = []
        for e in el.findall("entry"):
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Encryption": _members_el(e.find("encryption")),
                    "Authentication": _members_el(e.find("authentication")),
                    "DH Group": _members_el(e.find("dh-group")),
                }
            )
        return rows

    def get_zone_protection_profiles(self) -> list:
        net = self._net()
        if net is None:
            return []
        el = net.find("profiles/zone-protection-profile")
        if el is None:
            return []
        rows = []
        for e in el.findall("entry"):
            flood = e.find("flood")

            def _flood(tag):
                f = flood.find(tag) if flood else None
                return _tick(f.findtext("enable", "no")) if f else ""

            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "SYN Flood": _flood("tcp-syn"),
                    "UDP Flood": _flood("udp"),
                    "ICMP Flood": _flood("icmp"),
                    "ICMPv6 Flood": _flood("icmpv6"),
                    "Other IP": _flood("other"),
                    "Description": e.findtext("description", "-"),
                }
            )
        return rows

    def get_lldp_profiles(self) -> list:
        net = self._net()
        if net is None:
            return []
        el = net.find("profiles/lldp-profile")
        if el is None:
            return []
        rows = []
        for e in el.findall("entry"):
            tlv = e.find("optional-tlv")
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Mode": e.findtext("mode", "-"),
                    "SNMP Notif": _tick(e.findtext("snmp-notification-enable", "no")),
                    "Syslog": _tick(e.findtext("syslog-enable", "no")),
                    "Port Desc": (
                        _tick(tlv.findtext("port-description", "no")) if tlv else ""
                    ),
                    "Sys Name": _tick(tlv.findtext("system-name", "no")) if tlv else "",
                    "Sys Desc": (
                        _tick(tlv.findtext("system-description", "no")) if tlv else ""
                    ),
                    "Sys Caps": (
                        _tick(tlv.findtext("system-capabilities", "no")) if tlv else ""
                    ),
                    "Mgmt Addr": (
                        _tick(tlv.findtext("management-address", "no")) if tlv else ""
                    ),
                }
            )
        return rows

    def get_bfd_profiles(self) -> list:
        net = self._net()
        if net is None:
            return []
        # Try multiple locations
        for path in ["bfd-profile", "profiles/bfd-profile"]:
            el = net.find(path)
            if el is not None:
                rows = []
                for e in el.findall("entry"):
                    tm = e.find("timers")

                    def _tv(tag, alt):
                        return (tm.findtext(tag) if tm else None) or e.findtext(
                            alt, "-"
                        )

                    rows.append(
                        {
                            "Name": e.get("name", "-"),
                            "Mode": e.findtext("mode", "-"),
                            "Min TX (ms)": _tv(
                                "desired-min-tx-interval", "min-tx-interval"
                            ),
                            "Min RX (ms)": _tv(
                                "required-min-rx-interval", "min-rx-interval"
                            ),
                            "Multiplier": _tv("detection-multiplier", "multiplier"),
                            "Hold Time": e.findtext(
                                "hold-time", e.findtext("hold-off-time", "-")
                            ),
                            "Multihop": _tick(e.findtext("multihop", "no")),
                        }
                    )
                return rows
        return []

    def get_gre_tunnels(self) -> list:
        net = self._net()
        if net is None:
            return []
        gre_el = net.find("tunnel/gre")
        if gre_el is None:
            return []
        zone_map = self._build_zone_map()
        vr_map = self._build_vr_map()
        rows = []
        for e in gre_el.findall("entry"):
            tun = e.findtext("tunnel-interface", "-")
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Src Interface": e.findtext("local-address/interface", "-"),
                    "Local IP": e.findtext("local-address/ip", "-"),
                    "Peer IP": e.findtext("peer-address", "-"),
                    "Tunnel Intf": tun,
                    "VR": vr_map.get(tun, "-"),
                    "Zone": zone_map.get(tun, "-"),
                    "TTL": e.findtext("ttl", "-"),
                    "Keep Alive": _tick(e.findtext("keep-alive/enable", "no")),
                }
            )
        return rows

    def get_gp_mdm(self) -> list:
        gp = self.vsys.find("global-protect") if self.vsys else None
        if gp is None:
            return []
        rows = []
        for portal in gp.findall("global-protect-portal/entry"):
            pname = portal.get("name", "")
            for cfg in portal.findall(".//configs/entry"):
                mdm = cfg.find("mdm")
                if mdm is not None:
                    rows.append(
                        {
                            "Portal": pname,
                            "Config": cfg.get("name", "-"),
                            "Server": mdm.findtext("server-address", "-"),
                            "MDM Vendor": mdm.findtext("mdm-vendor", "-"),
                            "Client Cert": mdm.findtext(
                                "client-certificate-store", "-"
                            ),
                            "Status": "-",
                        }
                    )
        return rows

    def get_gp_ipsec_crypto(self) -> list:
        net = self._net()
        if net is None:
            return []
        el = net.find("ike/crypto-profiles/global-protect-ipsec-crypto-profiles")
        if el is None:
            return []
        rows = []
        for e in el.findall("entry"):
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Encryption": _members_el(e.find("encryption")),
                    "Authentication": _members_el(e.find("authentication")),
                    "DH Group": _members_el(e.find("dh-group")),
                }
            )
        return rows

    def get_zone_protection_profiles(self) -> list:
        net = self._net()
        if net is None:
            return []
        el = net.find("profiles/zone-protection-profile")
        if el is None:
            return []
        rows = []
        for e in el.findall("entry"):
            flood = e.find("flood")

            def _flood(tag):
                f = flood.find(tag) if flood else None
                return _tick(f.findtext("enable", "no")) if f else ""

            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "SYN Flood": _flood("tcp-syn"),
                    "UDP Flood": _flood("udp"),
                    "ICMP Flood": _flood("icmp"),
                    "ICMPv6 Flood": _flood("icmpv6"),
                    "Other IP": _flood("other"),
                    "Description": e.findtext("description", "-"),
                }
            )
        return rows

    def get_lldp_profiles(self) -> list:
        net = self._net()
        if net is None:
            return []
        el = net.find("profiles/lldp-profile")
        if el is None:
            return []
        rows = []
        for e in el.findall("entry"):
            tlv = e.find("optional-tlv")
            rows.append(
                {
                    "Name": e.get("name", "-"),
                    "Mode": e.findtext("mode", "-"),
                    "SNMP Notif": _tick(e.findtext("snmp-notification-enable", "no")),
                    "Syslog": _tick(e.findtext("syslog-enable", "no")),
                    "Port Desc": (
                        _tick(tlv.findtext("port-description", "no")) if tlv else ""
                    ),
                    "Sys Name": _tick(tlv.findtext("system-name", "no")) if tlv else "",
                    "Sys Desc": (
                        _tick(tlv.findtext("system-description", "no")) if tlv else ""
                    ),
                    "Sys Caps": (
                        _tick(tlv.findtext("system-capabilities", "no")) if tlv else ""
                    ),
                    "Mgmt Addr": (
                        _tick(tlv.findtext("management-address", "no")) if tlv else ""
                    ),
                }
            )
        return rows

    def get_bfd_profiles(self) -> list:
        net = self._net()
        if net is None:
            return []
        # Try multiple locations
        for path in ["bfd-profile", "profiles/bfd-profile"]:
            el = net.find(path)
            if el is not None:
                rows = []
                for e in el.findall("entry"):
                    tm = e.find("timers")

                    def _tv(tag, alt):
                        return (tm.findtext(tag) if tm else None) or e.findtext(
                            alt, "-"
                        )

                    rows.append(
                        {
                            "Name": e.get("name", "-"),
                            "Mode": e.findtext("mode", "-"),
                            "Min TX (ms)": _tv(
                                "desired-min-tx-interval", "min-tx-interval"
                            ),
                            "Min RX (ms)": _tv(
                                "required-min-rx-interval", "min-rx-interval"
                            ),
                            "Multiplier": _tv("detection-multiplier", "multiplier"),
                            "Hold Time": e.findtext(
                                "hold-time", e.findtext("hold-off-time", "-")
                            ),
                            "Multihop": _tick(e.findtext("multihop", "no")),
                        }
                    )
                return rows
        return []
