"""Palo Alto base parser - shared XML utilities."""

import xml.etree.ElementTree as ET


def _txt(el, tag, default=""):
    if el is None:
        return default
    c = el.find(tag)
    return c.text.strip() if c is not None and c.text else default


def _members_el(el, default="any"):
    if el is None:
        return default
    items = [m.text for m in el.findall("member") if m.text]
    return ", ".join(items) if items else default


def _is_disabled(entry):
    d = entry.find("disabled")
    return d is not None and (d.text or "").strip().lower() == "yes"


def _addr_with_negate(entry, addr_tag, negate_tag):
    negate_el = entry.find(negate_tag)
    negate = negate_el is not None and (negate_el.text or "").strip().lower() == "yes"
    addr_el = entry.find(addr_tag)
    members = (
        [m.text for m in addr_el.findall("member") if m.text]
        if addr_el is not None
        else []
    )
    if not members:
        return "any"
    if negate:
        return ", ".join(f"~~{a}~~" for a in members)
    return ", ".join(members)


class PaloAltoParser:
    """Unified Palo Alto parser - entry point used by app.py."""

    def __init__(self, content):
        if isinstance(content, ET.Element):
            self.root = content
            self.content = ET.tostring(content, encoding="unicode")
        else:
            self.content = content
            try:
                self.root = ET.fromstring(content)
            except ET.ParseError:
                self.root = None

        self.dev = self.root.find(".//devices/entry") if self.root is not None else None

        self.vsys = None
        self.rb = None

        if self.dev is not None:
            self.vsys = self.dev.find('vsys/entry[@name="vsys1"]')

            if self.vsys is not None:
                self.rb = self.vsys.find("rulebase")

    def get_hostname(self) -> str:
        sys_el = self.dev.find("deviceconfig/system") if self.dev is not None else None
        return _txt(sys_el, "hostname", "Unknown")

    def get_system_info(self) -> dict:
        sys_el = self.dev.find("deviceconfig/system") if self.dev is not None else None
        version = ""
        if self.root is not None:
            version = self.root.get("detail-version") or self.root.get("version") or ""

        def g(tag, default="-"):
            return _txt(sys_el, tag, default)

        # MGT default gateway from static route
        route = sys_el.find("route") if sys_el is not None else None
        gw = ""
        if route is not None:
            for entry in route.findall("entry"):
                nh = entry.find("nexthop/ip-address")
                if nh is not None and nh.text:
                    gw = nh.text
                    break

        # Advanced routing
        setting = self.dev.find("deviceconfig/setting") if self.dev else None
        adv_routing = "Off"
        dup_ip = "Disable"
        if setting is not None:
            ar = setting.find("advanced-routing/enable")
            if ar is not None and ar.text and ar.text.lower() == "yes":
                adv_routing = "On"
            di = setting.find("management/enable-duplicate-mac-detect")
            if di is not None and di.text and di.text.lower() == "yes":
                dup_ip = "Enable"

        return {
            "hostname": g("hostname", "Unknown"),
            "ip_address": g("ip-address", "-"),
            "netmask": g("netmask", "-"),
            "default_gateway": gw,
            "ipv6_address": g("ipv6-address", "Unknown"),
            "ipv6_link_local": g("ipv6-link-local-address", "Unknown"),
            "ipv6_gateway": g("ipv6-default-gateway", ""),
            "software_version": version,
            "timezone": g("timezone", "-"),
            "adv_routing": adv_routing,
            "dup_ip": dup_ip,
        }

    def get_ha_info(self) -> dict:
        ha = (
            self.dev.find("deviceconfig/high-availability")
            if self.dev is not None
            else None
        )
        if ha is None:
            return {"enabled": False}
        enabled_el = ha.find("enabled")
        if enabled_el is None or (enabled_el.text or "").strip().lower() != "yes":
            return {"enabled": False}
        group = ha.find("group")
        mode = "active-passive"
        if group is not None:
            mode_el = group.find("mode")
            if mode_el is not None and mode_el.find("active-active") is not None:
                mode = "active-active"
        peer_ip = _txt(group, "peer-ip", "-") if group is not None else "-"
        ha1 = ha.find("interface/ha1")
        ha1_ip = _txt(ha1, "ip-address", "-") if ha1 is not None else "-"
        ha1_port = _txt(ha1, "port", "-") if ha1 is not None else "-"
        ha2 = ha.find("interface/ha2")
        ha2_ip = _txt(ha2, "ip-address", "-") if ha2 is not None else "-"
        group_id = _txt(group, "group-id", "-") if group is not None else "-"
        return {
            "enabled": True,
            "mode": mode,
            "peer_ip": peer_ip,
            "ha1_ip": ha1_ip,
            "ha1_port": ha1_port,
            "ha2_ip": ha2_ip,
            "group_id": group_id,
        }

    def get_zones_list(self) -> list:
        if self.vsys is None:
            return []
        return [e.get("name", "") for e in self.vsys.findall("zone/entry")]

    def get_interfaces_list(self) -> list:
        net = self.dev.find("network/interface") if self.dev else None
        if net is None:
            return []
        result = []
        for itype in ["ethernet", "aggregate-ethernet", "loopback", "tunnel", "sdwan"]:
            el = net.find(itype)
            if el is not None:
                for e in el.findall("entry"):
                    result.append(e.get("name", ""))
                    for u in e.findall(".//units/entry"):
                        result.append(u.get("name", ""))
        return result
