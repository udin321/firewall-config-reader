import re
import ipaddress
from .base import BaseFirewallParser
from .security_parser import SecurityProfileMixin
from .vpn_parser import VPNParserMixin
from .user_parser import UserParserMixin
from .wifi_parser import WiFiParserMixin
from .system_parser import SystemParserMixin


class FortiGateParser(
    BaseFirewallParser,
    SecurityProfileMixin,
    VPNParserMixin,
    UserParserMixin,
    WiFiParserMixin,
    SystemParserMixin,
):

    def _extract_block(self, keyword: str) -> str:
        start_marker = f"config {keyword}"
        start = self.content.find(start_marker)
        if start == -1:
            return ""
        depth = 0
        lines = self.content[start:].splitlines()
        collected = []
        for line in lines:
            stripped = line.strip()
            collected.append(line)
            if stripped.startswith("config "):
                depth += 1
            elif stripped == "end":
                depth -= 1
                if depth == 0:
                    break
        return "\n".join(collected)

    def _extract_sub_block(self, parent_block: str, keyword: str) -> str:
        marker = f"config {keyword}"
        start = parent_block.find(marker)
        if start == -1:
            return ""
        depth = 0
        lines = parent_block[start:].splitlines()
        collected = []
        for line in lines:
            stripped = line.strip()
            collected.append(line)
            if stripped.startswith("config "):
                depth += 1
            elif stripped == "end":
                depth -= 1
                if depth == 0:
                    break
        return "\n".join(collected)

    def get_hostname(self) -> str:
        m = re.search(r'set hostname "?([^"\s]+)"?', self.content)
        return m.group(1) if m else "Unknown"

    def get_serial_number(self) -> str:
        # Prefer explicit serial number
        m = re.search(r'set sn "?([^"\s]+)"?', self.content)
        if m:
            return m.group(1)

        # Find all csf-device values
        matches = re.findall(r'set csf-device "?([^"\s]+)"?', self.content)

        # Return first value that looks like a FortiGate serial
        for val in matches:
            if re.match(r"^FG[A-Z0-9]+$", val) and val.lower() != "all":
                return val

        return "Unknown"

    def get_firmware_version(self) -> str:
        m = re.search(r"config-version=\S+-(.+?)-FW", self.content)
        if not m:
            m = re.search(r"config-version=\S+?-([\w\.\-]+)", self.content)
        return m.group(1) if m else "Unknown"

    def get_wan_ip(self) -> str:
        block = self._extract_block("system interface")
        if not block:
            return "Unknown"
        entries = re.findall(
            r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE
        )
        for name, body in entries:
            is_wan_name = re.match(r"wan\d*", name, re.IGNORECASE)
            is_wan_role = re.search(r"set role wan", body, re.IGNORECASE)
            is_wan_type = re.search(r"set type wan", body, re.IGNORECASE)
            ip_m = re.search(r"set ip ([\d\.]+) ([\d\.]+)", body)
            if (is_wan_name or is_wan_role or is_wan_type) and ip_m:
                return f"{ip_m.group(1)}/{ip_m.group(2)}"
        return "Not configured"

    def get_ha_config(self) -> dict:
        body = self._extract_block("system ha")
        if not body:
            return {"enabled": False}
        mode_m = re.search(r"set mode (\S+)", body)
        mode = mode_m.group(1) if mode_m else None
        if not mode or mode.lower() == "standalone":
            return {"enabled": False}
        mode_labels = {"a-p": "Active-Passive", "a-a": "Active-Active"}
        group_m = re.search(r'set group-name "([^"]+)"', body)
        pri_m = re.search(r"set priority (\d+)", body)
        hbdev_m = re.search(r'set hbdev "([^"]+)"', body)
        pickup_m = re.search(r"set session-pickup (\S+)", body)
        override_m = re.search(r"set override (\S+)", body)
        return {
            "enabled": True,
            "mode": mode_labels.get(mode.lower(), mode.upper()),
            "group_name": group_m.group(1) if group_m else "-",
            "priority": pri_m.group(1) if pri_m else "-",
            "heartbeat_dev": hbdev_m.group(1) if hbdev_m else "-",
            "session_pickup": pickup_m.group(1).capitalize() if pickup_m else "-",
            "override": override_m.group(1).capitalize() if override_m else "-",
        }

    def get_dns(self) -> dict:
        body = self._extract_block("system dns")
        if not body:
            return {"primary": "Unknown", "secondary": "Unknown"}
        pri_m = re.search(r"set primary ([\d\.]+)", body)
        sec_m = re.search(r"set secondary ([\d\.]+)", body)
        return {
            "primary": pri_m.group(1) if pri_m else "Not set",
            "secondary": sec_m.group(1) if sec_m else "Not set",
        }

    def _parse_dhcp_map(self) -> dict:
        dhcp_map = {}
        block = self._extract_block("system dhcp server")
        if not block:
            return dhcp_map
        for entry in re.findall(r"edit \d+(.*?)next", block, re.DOTALL):
            intf_m = re.search(r'set interface "([^"]+)"', entry)
            start_m = re.search(r"set start-ip ([\d\.]+)", entry)
            end_m = re.search(r"set end-ip ([\d\.]+)", entry)
            if intf_m:
                dhcp_map[intf_m.group(1)] = (
                    f"{start_m.group(1)}-{end_m.group(1)}" if start_m and end_m else "-"
                )
        return dhcp_map

    def _parse_raw_interfaces(self, dhcp_map: dict) -> dict:
        interfaces = {}
        block = self._extract_block("system interface")
        if not block:
            return interfaces
        entries = re.findall(
            r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE
        )
        for name, body in entries:
            type_m = re.search(r"set type (\w+)", body)
            ip_m = re.search(r"set ip ([\d\.]+) ([\d\.]+)", body)
            acc_m = re.search(r"set allowaccess (.*)", body)
            parent_m = re.search(r'set interface "([^"]+)"', body)
            alias_m = re.search(r'set alias "([^"]+)"', body)
            role_m = re.search(r"set role (\w+)", body)
            vdom_m = re.search(r'set vdom "([^"]+)"', body)
            status_m = re.search(r"set status (enable|disable)", body)
            # Hardware switch members: set member "portA" "portB"
            mem_raw = re.search(r"set member (.*)", body)
            members = ""
            if mem_raw:
                members = " ".join(re.findall(r'"([^"]+)"', mem_raw.group(1)))
            # Also handle set members (typo variant)
            if not members:
                mem_m2 = re.search(r'set (?:memebrs|members) "([^"]+)"', body)
                if mem_m2:
                    members = mem_m2.group(1).replace('"', "")

            interfaces[name] = {
                "Name": name,
                "Alias": alias_m.group(1) if alias_m else "-",
                "VDOM": vdom_m.group(1) if vdom_m else "-",
                "Type": type_m.group(1).capitalize() if type_m else "Physical",
                "Role": role_m.group(1).capitalize() if role_m else "-",
                "Members": members if members else "-",
                "IP/Netmask": f"{ip_m.group(1)}/{ip_m.group(2)}" if ip_m else "-",
                "Admin Access": (
                    acc_m.group(1).upper().replace(" ", ", ") if acc_m else "-"
                ),
                "DHCP Range": dhcp_map.get(name, "-"),
                "Status": status_m.group(1).capitalize() if status_m else "Enable",
                "Parent": parent_m.group(1) if parent_m else None,
            }
        return interfaces

    def _parse_zones(self) -> list:
        """Parse system zones and return list of zone dicts with member interfaces."""
        block = self._extract_block("system zone")
        if not block:
            return []
        zones = []
        entries = re.findall(
            r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE
        )
        for name, body in entries:
            intf_m = re.search(r"set interface (.*)", body)
            members = []
            if intf_m:
                members = re.findall(r'"([^"]+)"', intf_m.group(1))
            intrazone_m = re.search(r"set intrazone (\S+)", body)
            zones.append(
                {
                    "zone_name": name,
                    "members": members,
                    "intrazone": intrazone_m.group(1) if intrazone_m else "deny",
                }
            )
        return zones

    def parse_interfaces(self) -> list:
        dhcp_map = self._parse_dhcp_map()
        interfaces = self._parse_raw_interfaces(dhcp_map)
        zones = self._parse_zones()

        final_rows = []
        seen = set()

        def add_node(name, level=0, zone_name=None):
            if name in seen or name not in interfaces:
                return
            item = interfaces[name]
            prefix = "\u00a0\u00a0\u00a0" * level + ("\u2517 " if level > 0 else "")
            row = {
                "Name": prefix + item["Name"],
                "Alias": item["Alias"],
                "VDOM": item["VDOM"],
                "Type": item["Type"],
                "Role": item["Role"],
                "Members": item["Members"],
                "IP/Netmask": item["IP/Netmask"],
                "Admin Access": item["Admin Access"],
                "DHCP Range": item["DHCP Range"],
                "Status": item["Status"],
                "Zone": zone_name if zone_name else "-",
            }
            final_rows.append(row)
            seen.add(name)
            # Add children (VLANs, sub-interfaces with this as parent)
            for child_name, child_info in interfaces.items():
                if child_info["Parent"] == name:
                    add_node(child_name, level + 1, zone_name)

        # Build zone membership map
        zone_member_map = {}
        for z in zones:
            for m in z["members"]:
                zone_member_map[m] = z["zone_name"]

        # Add zone rows first as headers, then their members
        zone_members_added = set()
        for z in zones:
            # Zone header row
            final_rows.append(
                {
                    "Name": f"\U0001f4e6 {z['zone_name']}",
                    "Alias": "-",
                    "VDOM": "-",
                    "Type": "Zone",
                    "Role": "-",
                    "Members": ", ".join(z["members"]),
                    "IP/Netmask": "-",
                    "Admin Access": "-",
                    "DHCP Range": "-",
                    "Status": "Enable",
                    "Zone": z["zone_name"],
                }
            )
            for m in z["members"]:
                add_node(m, level=1, zone_name=z["zone_name"])
                zone_members_added.add(m)

        # Process remaining top-level interfaces (not in zones, no parent)
        for name in sorted(interfaces.keys()):
            if not interfaces[name]["Parent"] and name not in seen:
                add_node(name, zone_name=zone_member_map.get(name))

        return final_rows

    def parse_policies(self) -> list:
        block = self._extract_block("firewall policy")
        if not block:
            return []
        rows = []
        entries = re.findall(
            r"^\s*edit (\d+)(.*?)^\s*next", block, re.DOTALL | re.MULTILINE
        )
        for policy_id, body in entries:
            name_m = re.search(r'set name "([^"]+)"', body)
            nat_m = re.search(r"set nat (enable|disable)", body)
            status_m = re.search(r"set status (enable|disable)", body)
            log_m = re.search(r"set logtraffic (\S+)", body)
            action_m = re.search(r"set action (\w+)", body)
            action = action_m.group(1) if action_m else "-"

            # Multi-value fields: set srcintf "a" "b" or set srcaddr "x" "y"
            def get_multi(keyword):
                m = re.search(rf"set {keyword} (.*)", body)
                if not m:
                    return "-"
                vals = re.findall(r'"([^"]+)"', m.group(1))
                return ", ".join(vals) if vals else m.group(1).strip()

            rows.append(
                {
                    "ID": policy_id,
                    "Name": name_m.group(1) if name_m else "-",
                    "Src Interface": get_multi("srcintf"),
                    "Dst Interface": get_multi("dstintf"),
                    "Source": get_multi("srcaddr"),
                    "Destination": get_multi("dstaddr"),
                    "Service": get_multi("service"),
                    "Schedule": get_multi("schedule"),
                    "Action": action.upper() if action != "-" else "-",
                    "NAT": nat_m.group(1).capitalize() if nat_m else "-",
                    "Status": status_m.group(1).capitalize() if status_m else "Enable",
                    "Log": log_m.group(1).capitalize() if log_m else "-",
                }
            )
        return rows

    def parse_proxy_policy(self) -> list:
        block = self._extract_block("firewall proxy-policy")
        if not block:
            return []
        rows = []
        entries = re.findall(
            r"^\s*edit (\d+)(.*?)^\s*next", block, re.DOTALL | re.MULTILINE
        )
        for policy_id, body in entries:
            name_m = re.search(r'set name "([^"]+)"', body)
            status_m = re.search(r"set status (enable|disable)", body)
            action_m = re.search(r"set action (\w+)", body)
            log_m = re.search(r"set logtraffic (\S+)", body)
            proxy_m = re.search(r"set proxy (\S+)", body)

            def get_field(pattern, b=body):
                m = re.search(pattern, b)
                return m.group(1).strip() if m else "-"

            rows.append(
                {
                    "ID": policy_id,
                    "Name": name_m.group(1) if name_m else "-",
                    "Proxy": proxy_m.group(1).capitalize() if proxy_m else "-",
                    "Src Interface": get_field(r'set srcintf "([^"]+)"'),
                    "Dst Interface": get_field(r'set dstintf "([^"]+)"'),
                    "Source": get_field(r'set srcaddr "([^"]+)"'),
                    "Destination": get_field(r'set dstaddr "([^"]+)"'),
                    "Service": get_field(r'set service "([^"]+)"'),
                    "Action": action_m.group(1).upper() if action_m else "-",
                    "Status": status_m.group(1).capitalize() if status_m else "Enable",
                    "Log": log_m.group(1).capitalize() if log_m else "-",
                }
            )
        return rows

    def parse_auth_rules(self) -> list:
        rows = []
        block = self._extract_block("firewall auth-portal")
        if block:
            intf_m = re.search(r'set identity-based-route "([^"]+)"', block)
            portal_m = re.search(r'set portal-addr "([^"]+)"', block)
            if intf_m or portal_m:
                rows.append(
                    {
                        "Type": "Auth Portal",
                        "Setting": intf_m.group(1) if intf_m else "-",
                        "Portal": portal_m.group(1) if portal_m else "-",
                    }
                )
        block2 = self._extract_block("user setting")
        if block2:
            auth_type_m = re.search(r"set auth-type (.*)", block2)
            auth_portal_m = re.search(r'set auth-portal-addr "([^"]+)"', block2)
            rows.append(
                {
                    "Type": "User Auth Setting",
                    "Setting": auth_type_m.group(1).strip() if auth_type_m else "-",
                    "Portal": auth_portal_m.group(1) if auth_portal_m else "-",
                }
            )
        return rows

    def parse_addresses(self) -> dict:

        subnet_list = []
        fqdn_list = []
        ipmask_list = []
        group_list = []
        iprange_list = []
        regex_list = []
        other_list = []

        block = self._extract_block("firewall address")
        if block:
            entries = re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE
            )
            for name, body in entries:
                type_m = re.search(r"set type (\S+)", body)
                subnet_m = re.search(r"set subnet ([\d\.]+) ([\d\.]+)", body)
                fqdn_m = re.search(r'set fqdn "([^"]+)"', body)
                intf_m = re.search(r'set interface "([^"]+)"', body)
                start_m = re.search(r"set start-ip ([\d\.]+)", body)
                end_m = re.search(r"set end-ip ([\d\.]+)", body)
                comment_m = re.search(r'set comment "([^"]+)"', body)
                addr_type = type_m.group(1) if type_m else "ipmask"
                base = {
                    "Name": name,
                    "Interface": intf_m.group(1) if intf_m else "any",
                    "Comment": comment_m.group(1) if comment_m else "-",
                }
                if addr_type == "fqdn":
                    fqdn_list.append(
                        {
                            **base,
                            "FQDN": fqdn_m.group(1) if fqdn_m else "-",
                            "Type": "FQDN",
                        }
                    )
                elif addr_type == "iprange":

                    start_ip = start_m.group(1) if start_m else "-"
                    end_ip = end_m.group(1) if end_m else "-"

                    iprange_list.append(
                        {
                            **base,
                            "Type": "IP Range",
                            # ====================================
                            # NEW RESOLVER FIELDS
                            # ====================================
                            "start_int": (
                                int(ipaddress.IPv4Address(start_ip))
                                if start_ip != "-"
                                else None
                            ),
                            "end_int": (
                                int(ipaddress.IPv4Address(end_ip))
                                if end_ip != "-"
                                else None
                            ),
                        }
                    )

                elif addr_type == "interface-subnet":
                    ipmask_list.append(
                        {
                            **base,
                            "Details": (
                                f"{subnet_m.group(1)}/{subnet_m.group(2)}"
                                if subnet_m
                                else "-"
                            ),
                            "Type": "Interface Subnet",
                        }
                    )
                else:
                    if subnet_m:
                        subnet_ip = subnet_m.group(1)
                        subnet_mask = subnet_m.group(2)

                        network = ipaddress.IPv4Network(
                            f"{subnet_ip}/{subnet_mask}", strict=False
                        )

                        subnet_list.append(
                            {
                                **base,
                                "Details": f"{subnet_ip}/{subnet_mask}",
                                "Type": "Subnet",
                                # ====================================
                                # NEW RESOLVER FIELDS
                                # ====================================
                                "network": str(network.network_address),
                                "broadcast": str(network.broadcast_address),
                                "prefixlen": network.prefixlen,
                                # important for lookup
                            }
                        )
                    else:
                        other_list.append({**base, "Details": "-", "Type": addr_type})

        grp_block = self._extract_block("firewall addrgrp")
        if grp_block:
            entries = re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next', grp_block, re.DOTALL | re.MULTILINE
            )
            for name, body in entries:
                member_m = re.search(r"set member (.*)", body)
                comment_m = re.search(r'set comment "([^"]+)"', body)
                members = ""
                if member_m:
                    members = ", ".join(re.findall(r'"([^"]+)"', member_m.group(1)))
                group_list.append(
                    {
                        "Name": name,
                        "Members": members or "-",
                        "Comment": comment_m.group(1) if comment_m else "-",
                        "Type": "Address Group",
                    }
                )

        proxy_block = self._extract_block("firewall proxy-address")
        if proxy_block:
            entries = re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next',
                proxy_block,
                re.DOTALL | re.MULTILINE,
            )
            for name, body in entries:
                type_m = re.search(r"set type (\S+)", body)
                regex_m = re.search(r'set host-regex "([^"]+)"', body)
                intf_m = re.search(r'set interface "([^"]+)"', body)
                regex_list.append(
                    {
                        "Name": name,
                        "Type": (
                            type_m.group(1).replace("-", " ").title() if type_m else "-"
                        ),
                        "Regex": regex_m.group(1) if regex_m else "-",
                        "Interface": intf_m.group(1) if intf_m else "any",
                    }
                )

        return {
            "subnet": subnet_list,
            "fqdn": fqdn_list,
            "iprange": iprange_list,
            "ipmask": ipmask_list,
            "groups": group_list,
            "regex": regex_list,
            "other": other_list,
        }

    def parse_services(self) -> dict:
        categories = {}
        cat_block = self._extract_block("firewall service category")
        if cat_block:
            for entry in re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next', cat_block, re.DOTALL | re.MULTILINE
            ):
                name, body = entry
                comment_m = re.search(r'set comment "([^"]+)"', body)
                categories[name] = comment_m.group(1) if comment_m else ""

        services = []
        svc_block = self._extract_block("firewall service custom")
        if svc_block:
            entries = re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next', svc_block, re.DOTALL | re.MULTILINE
            )
            for name, body in entries:
                cat_m = re.search(r'set category "([^"]+)"', body)
                proto_m = re.search(r"set protocol (\S+)", body)
                tcp_m = re.search(r"set tcp-portrange ([\d\s:]+)", body)
                udp_m = re.search(r"set udp-portrange ([\d\s:]+)", body)
                ipproto_m = re.search(r"set protocol-number (\d+)", body)
                fqdn_m = re.search(r'set fqdn "([^"]+)"', body)
                comment_m = re.search(r'set comment "([^"]+)"', body)
                icmp_m = re.search(r"set icmptype (\d+)", body)
                proto = proto_m.group(1).upper() if proto_m else "TCP/UDP"
                details_parts = []
                if tcp_m:
                    details_parts.append(f"TCP: {tcp_m.group(1).strip()}")
                if udp_m:
                    details_parts.append(f"UDP: {udp_m.group(1).strip()}")
                if icmp_m:
                    details_parts.append(f"ICMP Type: {icmp_m.group(1)}")
                if ipproto_m:
                    details_parts.append(f"IP Proto: {ipproto_m.group(1)}")
                services.append(
                    {
                        "Name": name,
                        "Category": cat_m.group(1) if cat_m else "-",
                        "Protocol": proto,
                        "Details": " | ".join(details_parts) if details_parts else "-",
                        "IP/FQDN": fqdn_m.group(1) if fqdn_m else "-",
                        "Comment": comment_m.group(1) if comment_m else "-",
                    }
                )
        return {"categories": list(categories.keys()), "services": services}

    def parse_schedules(self) -> list:
        rows = []
        st_block = self._extract_block("system speed-test-schedule")
        if st_block:
            for entry in re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next', st_block, re.DOTALL | re.MULTILINE
            ):
                name, body = entry
                sched_m = re.search(r'set schedules "([^"]+)"', body)
                inband_m = re.search(r"set update-inbandwidth (enable|disable)", body)
                outband_m = re.search(r"set update-outbandwidth (enable|disable)", body)
                rows.append(
                    {
                        "Name": name,
                        "Type": "Speed Test",
                        "Schedule": sched_m.group(1) if sched_m else "-",
                        "Update In-BW": (
                            inband_m.group(1).capitalize() if inband_m else "-"
                        ),
                        "Update Out-BW": (
                            outband_m.group(1).capitalize() if outband_m else "-"
                        ),
                    }
                )
        rec_block = self._extract_block("firewall schedule recurring")
        if rec_block:
            for entry in re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next', rec_block, re.DOTALL | re.MULTILINE
            ):
                name, body = entry
                day_m = re.search(r"set day (.*)", body)
                start_m = re.search(r"set start (\S+)", body)
                end_m = re.search(r"set end (\S+)", body)
                rows.append(
                    {
                        "Name": name,
                        "Type": "Recurring",
                        "Schedule": day_m.group(1).strip() if day_m else "daily",
                        "Update In-BW": start_m.group(1) if start_m else "-",
                        "Update Out-BW": end_m.group(1) if end_m else "-",
                    }
                )
        once_block = self._extract_block("firewall schedule onetime")
        if once_block:
            for entry in re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next', once_block, re.DOTALL | re.MULTILINE
            ):
                name, body = entry
                start_m = re.search(r"set start (.*)", body)
                end_m = re.search(r"set end (.*)", body)
                rows.append(
                    {
                        "Name": name,
                        "Type": "One-time",
                        "Schedule": f"{start_m.group(1).strip() if start_m else '-'} to {end_m.group(1).strip() if end_m else '-'}",
                        "Update In-BW": "-",
                        "Update Out-BW": "-",
                    }
                )
        return rows

    def parse_vip(self) -> list:
        block = self._extract_block("firewall vip")
        if not block:
            return []
        rows = []
        entries = re.findall(
            r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE
        )
        for name, body in entries:
            extip_m = re.search(r"set extip ([\d\.]+)", body)
            mappedip_m = re.search(r'set mappedip "([^"]+)"', body)
            extintf_m = re.search(r'set extintf "([^"]+)"', body)
            service_m = re.search(r"set service (.*)", body)
            extport_m = re.search(r"set extport (\d+)", body)
            mappedport_m = re.search(r"set mappedport (\d+)", body)
            type_m = re.search(r"set type (\S+)", body)
            proto_m = re.search(r"set protocol (\S+)", body)
            ext_display = extip_m.group(1) if extip_m else "-"
            if extport_m:
                ext_display += f":{extport_m.group(1)}"
            map_display = mappedip_m.group(1) if mappedip_m else "-"
            if mappedport_m:
                map_display += f":{mappedport_m.group(1)}"
            services = ""
            if service_m:
                services = ", ".join(re.findall(r'"([^"]+)"', service_m.group(1)))
            rows.append(
                {
                    "Name": name,
                    "Interface": extintf_m.group(1) if extintf_m else "any",
                    "Type": (
                        type_m.group(1).replace("-", " ").title()
                        if type_m
                        else "Static NAT"
                    ),
                    "Protocol": proto_m.group(1).upper() if proto_m else "-",
                    "Service": services or "-",
                    "Mapped From": ext_display,
                    "Mapped To": map_display,
                }
            )
        return rows

    def parse_ip_pools(self) -> list:
        block = self._extract_block("firewall ippool")
        if not block:
            return []
        rows = []
        entries = re.findall(
            r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE
        )
        for name, body in entries:
            start_m = re.search(r"set startip ([\d\.]+)", body)
            end_m = re.search(r"set endip ([\d\.]+)", body)
            type_m = re.search(r"set type (\S+)", body)
            arp_m = re.search(r"set arp-reply (enable|disable)", body)
            comment_m = re.search(r'set comments "([^"]+)"', body)
            rows.append(
                {
                    "Name": name,
                    "External IP Range": f"{start_m.group(1) if start_m else '-'} - {end_m.group(1) if end_m else '-'}",
                    "Type": (
                        type_m.group(1).replace("-", " ").title()
                        if type_m
                        else "Overload"
                    ),
                    "ARP Reply": arp_m.group(1).capitalize() if arp_m else "Enable",
                    "Comment": comment_m.group(1) if comment_m else "-",
                }
            )
        return rows

    def parse_protocol_options(self) -> list:
        block = self._extract_block("firewall profile-protocol-options")
        if not block:
            return []
        rows = []
        entries = re.findall(
            r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE
        )
        protocols = [
            "http",
            "ftp",
            "imap",
            "mapi",
            "pop3",
            "smtp",
            "nntp",
            "dns",
            "ssh",
        ]
        for name, body in entries:
            comment_m = re.search(r'set comment "([^"]+)"', body)
            for proto in protocols:
                sub = self._extract_sub_block(body, proto)
                if sub:
                    ports_m = re.search(r"set ports ([\d\s]+)", sub)
                    options_m = re.search(r"set options (.*)", sub)
                    rows.append(
                        {
                            "Profile": name,
                            "Protocol": proto.upper(),
                            "Ports": ports_m.group(1).strip() if ports_m else "-",
                            "Options": (
                                options_m.group(1).strip() if options_m else "default"
                            ),
                            "Comment": comment_m.group(1) if comment_m else "-",
                        }
                    )
        return rows

    def parse_traffic_shaping(self) -> list:
        block = self._extract_block("firewall shaper traffic-shaper")
        if not block:
            return []
        rows = []
        entries = re.findall(
            r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE
        )
        for name, body in entries:
            maxbw_m = re.search(r"set maximum-bandwidth (\d+)", body)
            guaranbw_m = re.search(r"set guaranteed-bandwidth (\d+)", body)
            priority_m = re.search(r"set priority (\S+)", body)
            perpol_m = re.search(r"set per-policy (enable|disable)", body)

            def fmt_bw(val):
                if not val:
                    return "-"
                kb = int(val)
                return f"{kb // 1024} Mbps" if kb >= 1024 else f"{kb} Kbps"

            rows.append(
                {
                    "Name": name,
                    "Guaranteed Bandwidth": fmt_bw(
                        guaranbw_m.group(1) if guaranbw_m else None
                    ),
                    "Max Bandwidth": fmt_bw(maxbw_m.group(1) if maxbw_m else None),
                    "Priority": (
                        priority_m.group(1).capitalize() if priority_m else "High"
                    ),
                    "Per Policy": (
                        perpol_m.group(1).capitalize() if perpol_m else "Disable"
                    ),
                    "Bandwidth Util": "-",
                    "Dropped Bytes": "-",
                }
            )
        return rows

    def parse_virtual_servers(self) -> list:
        block = self._extract_block("firewall vip")
        if not block:
            return []
        rows = []
        entries = re.findall(
            r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE
        )
        for name, body in entries:
            type_m = re.search(r"set type (\S+)", body)
            if not type_m or "server-load-balance" not in type_m.group(1):
                continue
            lbm_m = re.search(r"set ldb-method (\S+)", body)
            extip_m = re.search(r"set extip ([\d\.]+)", body)
            extport_m = re.search(r"set extport (\d+)", body)
            proto_m = re.search(r"set protocol (\S+)", body)
            rows.append(
                {
                    "Name": name,
                    "VIP": extip_m.group(1) if extip_m else "-",
                    "Port": extport_m.group(1) if extport_m else "-",
                    "Protocol": proto_m.group(1).upper() if proto_m else "-",
                    "LB Method": (
                        lbm_m.group(1).replace("-", " ").title() if lbm_m else "-"
                    ),
                }
            )
        return rows

    def parse_health_check(self) -> list:
        block = self._extract_block("firewall ldb-monitor")
        if not block:
            return []
        rows = []
        entries = re.findall(
            r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE
        )
        for name, body in entries:
            type_m = re.search(r"set type (\S+)", body)
            port_m = re.search(r"set port (\d+)", body)
            interval_m = re.search(r"set interval (\d+)", body)
            timeout_m = re.search(r"set timeout (\d+)", body)
            retry_m = re.search(r"set retry (\d+)", body)
            rows.append(
                {
                    "Name": name,
                    "Type": type_m.group(1).upper() if type_m else "-",
                    "Port": port_m.group(1) if port_m else "-",
                    "Interval": f"{interval_m.group(1)}s" if interval_m else "-",
                    "Timeout": f"{timeout_m.group(1)}s" if timeout_m else "-",
                    "Retry": retry_m.group(1) if retry_m else "-",
                }
            )
        return rows

    def parse_ipam(self) -> list:
        block = self._extract_block("system ipam")
        if not block:
            return []
        rows = []
        entries = re.findall(
            r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE
        )
        for name, body in entries:
            subnet_m = re.search(r"set subnet ([\d\.]+/\d+|[\d\.]+ [\d\.]+)", body)
            intf_m = re.search(r'set interface "([^"]+)"', body)
            desc_m = re.search(r'set description "([^"]+)"', body)
            rows.append(
                {
                    "Pool Name": name,
                    "Subnet": subnet_m.group(1) if subnet_m else "-",
                    "Interface": intf_m.group(1) if intf_m else "-",
                    "Description": desc_m.group(1) if desc_m else "-",
                }
            )
        status_m = re.search(r"set status (enable|disable)", block)
        pool_m = re.search(r"set pool-prefix ([\d\.\/]+)", block)
        if not rows and (status_m or pool_m):
            rows.append(
                {
                    "Pool Name": "Global",
                    "Subnet": pool_m.group(1) if pool_m else "-",
                    "Interface": "-",
                    "Description": f"Status: {status_m.group(1) if status_m else 'unknown'}",
                }
            )
        return rows

    def parse_fortiextender(self) -> list:
        block = self._extract_block("extender-controller extender")
        if not block:
            return []
        rows = []
        entries = re.findall(
            r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE
        )
        for name, body in entries:
            id_m = re.search(r'set id "([^"]+)"', body)
            admin_m = re.search(r"set admin (enable|disable)", body)
            profile_m = re.search(r'set profile "([^"]+)"', body)
            vdom_m = re.search(r'set vdom "([^"]+)"', body)
            desc_m = re.search(r'set description "([^"]+)"', body)
            rows.append(
                {
                    "Name": name,
                    "ID": id_m.group(1) if id_m else "-",
                    "Admin": admin_m.group(1).capitalize() if admin_m else "-",
                    "Profile": profile_m.group(1) if profile_m else "-",
                    "VDOM": vdom_m.group(1) if vdom_m else "-",
                    "Description": desc_m.group(1) if desc_m else "-",
                }
            )
        return rows

    def parse_sdwan(self) -> dict:
        block = self._extract_block("system sdwan")
        if not block:
            return {}
        status_m = re.search(r"set status (enable|disable)", block)
        zones = []
        zone_sub = self._extract_sub_block(block, "zone")
        if zone_sub:
            for entry in re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next', zone_sub, re.DOTALL | re.MULTILINE
            ):
                zone_name, _ = entry
                zones.append({"Zone Name": zone_name, "Members": []})
        if not zones:
            zones.append({"Zone Name": "virtual-wan-link", "Members": []})
        members_raw = []
        members_sub = self._extract_sub_block(block, "members")
        if members_sub:
            for entry in re.findall(
                r"^\s*edit (\d+)(.*?)^\s*next", members_sub, re.DOTALL | re.MULTILINE
            ):
                seq, body = entry
                intf_m = re.search(r'set interface "([^"]+)"', body)
                gw_m = re.search(r"set gateway ([\d\.]+)", body)
                zone_m = re.search(r'set zone "([^"]+)"', body)
                cost_m = re.search(r"set cost (\d+)", body)
                priority_m = re.search(r"set priority (\d+)", body)
                status2_m = re.search(r"set status (enable|disable)", body)
                intf_name = intf_m.group(1) if intf_m else "-"
                zone_name = (
                    zone_m.group(1)
                    if zone_m
                    else (zones[0]["Zone Name"] if zones else "virtual-wan-link")
                )
                members_raw.append(
                    {
                        "Seq": seq,
                        "Interface": intf_name,
                        "Zone": zone_name,
                        "Gateway": gw_m.group(1) if gw_m else "-",
                        "Cost": cost_m.group(1) if cost_m else "-",
                        "Priority": priority_m.group(1) if priority_m else "-",
                        "Status": (
                            status2_m.group(1).capitalize() if status2_m else "Enable"
                        ),
                    }
                )
                for z in zones:
                    if z["Zone Name"] == zone_name:
                        z["Members"].append(intf_name)
        health_checks = []
        hc_sub = self._extract_sub_block(block, "health-check")
        if hc_sub:
            for entry in re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next', hc_sub, re.DOTALL | re.MULTILINE
            ):
                hc_name, body = entry
                server_m = re.search(r"set server (.*)", body)
                protocol_m = re.search(r"set protocol (\S+)", body)
                interval_m = re.search(r"set interval (\d+)", body)
                recover_m = re.search(r"set recoverytime (\d+)", body)
                sysdns_m = re.search(r"set system-dns (enable|disable)", body)
                members_m = re.search(r"set members ([\d ]+)", body)
                latency_m = re.search(r"set latency-threshold (\d+)", body)
                jitter_m = re.search(r"set jitter-threshold (\d+)", body)
                pktloss_m = re.search(r"set packetloss-threshold (\d+)", body)
                if sysdns_m and sysdns_m.group(1) == "enable":
                    server = "System DNS"
                elif server_m:
                    server = server_m.group(1).replace('"', "").strip()
                else:
                    server = "-"
                health_checks.append(
                    {
                        "Name": hc_name,
                        "Detect Server": server,
                        "Protocol": (
                            protocol_m.group(1).upper() if protocol_m else "PING"
                        ),
                        "Interval (ms)": interval_m.group(1) if interval_m else "-",
                        "Recovery Threshold": recover_m.group(1) if recover_m else "-",
                        "Members": members_m.group(1).strip() if members_m else "All",
                        "Latency (ms)": latency_m.group(1) if latency_m else "-",
                        "Jitter (ms)": jitter_m.group(1) if jitter_m else "-",
                        "Pkt Loss (%)": pktloss_m.group(1) if pktloss_m else "-",
                    }
                )
        services = []
        svc_sub = self._extract_sub_block(block, "service")
        if svc_sub:
            for entry in re.findall(
                r"^\s*edit (\d+)(.*?)^\s*next", svc_sub, re.DOTALL | re.MULTILINE
            ):
                seq, body = entry
                name_m = re.search(r'set name "([^"]+)"', body)
                src_m = re.search(r"set src (.*)", body)
                dst_m = re.search(r"set dst (.*)", body)
                mode_m = re.search(r"set mode (\S+)", body)
                hc_m = re.search(r'set health-check "([^"]+)"', body)
                members_m = re.search(r"set priority-members ([\d ]+)", body)
                proto_m = re.search(r"set protocol (\d+)", body)
                sport_m = re.search(r"set start-port (\d+)", body)
                eport_m = re.search(r"set end-port (\d+)", body)
                cost_m = re.search(r"set link-cost-factor (\S+)", body)
                status2_m = re.search(r"set status (enable|disable)", body)

                def clean_list(raw):
                    if not raw:
                        return "-"
                    items = re.findall(r'"([^"]+)"', raw)
                    return ", ".join(items) if items else raw.strip()

                criteria_parts = []
                if mode_m:
                    criteria_parts.append(f"Mode: {mode_m.group(1).capitalize()}")
                if hc_m:
                    criteria_parts.append(f"SLA: {hc_m.group(1)}")
                if cost_m:
                    criteria_parts.append(
                        f"Cost: {cost_m.group(1).replace('-', ' ').title()}"
                    )
                criteria = (
                    " | ".join(criteria_parts) if criteria_parts else "Best Quality"
                )
                if sport_m and eport_m:
                    port = f"{sport_m.group(1)}-{eport_m.group(1)}"
                elif sport_m:
                    port = sport_m.group(1)
                else:
                    port = "-"
                proto_map = {"6": "TCP", "17": "UDP", "1": "ICMP"}
                proto_raw = proto_m.group(1) if proto_m else "-"
                proto = proto_map.get(proto_raw, proto_raw)
                services.append(
                    {
                        "ID": seq,
                        "Name": name_m.group(1) if name_m else "-",
                        "Source": clean_list(src_m.group(1) if src_m else None),
                        "Destination": clean_list(dst_m.group(1) if dst_m else None),
                        "Criteria": criteria,
                        "Members": members_m.group(1).strip() if members_m else "-",
                        "Performance SLA": hc_m.group(1) if hc_m else "-",
                        "Port": port,
                        "Protocol": proto,
                        "Status": (
                            status2_m.group(1).capitalize() if status2_m else "Enable"
                        ),
                    }
                )
        return {
            "status": status_m.group(1).capitalize() if status_m else "Disable",
            "zones": zones,
            "members": members_raw,
            "health_checks": health_checks,
            "services": services,
        }

    def parse_static_routes(self) -> list:
        block = self._extract_block("router static")
        if not block:
            return []
        rows = []
        entries = re.findall(
            r"^\s*edit (\d+)(.*?)^\s*next", block, re.DOTALL | re.MULTILINE
        )
        for seq, body in entries:
            dst_m = re.search(r"set dst ([\d\.]+) ([\d\.]+)", body)
            dstp_m = re.search(r"set dst ([\d\.]+/\d+)", body)
            gw_m = re.search(r"set gateway ([\d\.]+)", body)
            intf_m = re.search(r'set device "([^"]+)"', body)
            dist_m = re.search(r"set distance (\d+)", body)
            pri_m = re.search(r"set priority (\d+)", body)
            comment_m = re.search(r'set comment "([^"]+)"', body)
            status_m = re.search(r"set status (enable|disable)", body)
            bfd_m = re.search(r"set bfd (enable|disable)", body)
            if dst_m:
                dst = f"{dst_m.group(1)}/{dst_m.group(2)}"
            elif dstp_m:
                dst = dstp_m.group(1)
            else:
                dst = "-"
            rows.append(
                {
                    "Seq": seq,
                    "Destination": dst,
                    "Gateway": gw_m.group(1) if gw_m else "-",
                    "Interface": intf_m.group(1) if intf_m else "-",
                    "Distance": dist_m.group(1) if dist_m else "10",
                    "Priority": pri_m.group(1) if pri_m else "0",
                    "BFD": bfd_m.group(1).capitalize() if bfd_m else "-",
                    "Status": status_m.group(1).capitalize() if status_m else "Enable",
                    "Comment": comment_m.group(1) if comment_m else "-",
                }
            )
        return rows

    def parse_policy_routes(self) -> list:
        block = self._extract_block("router policy")
        if not block:
            return []
        rows = []
        entries = re.findall(
            r"^\s*edit (\d+)(.*?)^\s*next", block, re.DOTALL | re.MULTILINE
        )
        for seq, body in entries:
            # Multiple input devices
            input_dev_m = re.search(r"set input-device (.*)", body)
            input_devs = (
                re.findall(r'"([^"]+)"', input_dev_m.group(1)) if input_dev_m else []
            )

            # src/dst can be CIDR "172.16.x.x/255.x.x.x" or subnet notation
            def parse_addr(keyword):
                m = re.search(rf'set {keyword} "?([\d\.]+/[\d\.]+)"?', body)
                if m:
                    # Convert mask notation to CIDR if needed
                    parts = m.group(1).split("/")
                    if len(parts) == 2:
                        ip = parts[0]
                        mask = parts[1]
                        # If mask is dotted (e.g. 255.255.255.255), keep as is
                        if "." in mask:
                            return f"{ip}/{mask}"
                        return m.group(1)
                return "Any"

            gw_m = re.search(r"set gateway ([\d\.]+)", body)
            out_m = re.search(r'set output-device "([^"]+)"', body)
            proto_m = re.search(r"set protocol (\d+)", body)
            tos_m = re.search(r'set tos "([^"]+)"', body)
            comment_m = re.search(r'set comments "([^"]+)"', body)
            status_m = re.search(r"set status (enable|disable)", body)

            proto_map = {"6": "TCP", "17": "UDP", "1": "ICMP", "0": "Any"}
            proto_raw = proto_m.group(1) if proto_m else "0"
            proto = proto_map.get(proto_raw, proto_raw)

            rows.append(
                {
                    "Seq": seq,
                    "Source": parse_addr("src"),
                    "Destination": parse_addr("dst"),
                    "Input Interface": ", ".join(input_devs) if input_devs else "Any",
                    "Output Interface": out_m.group(1) if out_m else "-",
                    "Gateway": gw_m.group(1) if gw_m else "-",
                    "Protocol": proto,
                    "TOS": tos_m.group(1) if tos_m else "-",
                    "Comment": comment_m.group(1) if comment_m else "-",
                    "Status": status_m.group(1).capitalize() if status_m else "Enable",
                }
            )
        return rows

    def parse_rip(self) -> dict:
        block = self._extract_block("router rip")
        if not block:
            return {}
        version_m = re.search(r"set version (\d+)", block)
        defaultinfo_m = re.search(
            r"set default-information-originate (enable|disable)", block
        )
        distance_m = re.search(r"set default-metric (\d+)", block)
        networks = re.findall(r"set prefix ([\d\.\/]+)", block)
        interfaces = []
        intf_sub = self._extract_sub_block(block, "interface")
        if intf_sub:
            for entry in re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next', intf_sub, re.DOTALL | re.MULTILINE
            ):
                name, body = entry
                auth_m = re.search(r"set auth-type (\S+)", body)
                split_m = re.search(r"set split-horizon (\S+)", body)
                interfaces.append(
                    {
                        "Interface": name,
                        "Auth Type": auth_m.group(1).capitalize() if auth_m else "-",
                        "Split Horizon": (
                            split_m.group(1).capitalize() if split_m else "-"
                        ),
                    }
                )
        return {
            "version": version_m.group(1) if version_m else "-",
            "default_info": (
                defaultinfo_m.group(1).capitalize() if defaultinfo_m else "-"
            ),
            "default_metric": distance_m.group(1) if distance_m else "-",
            "networks": networks,
            "interfaces": interfaces,
        }

    def parse_ospf(self) -> dict:
        block = self._extract_block("router ospf")
        if not block:
            return {}
        router_id_m = re.search(r"set router-id ([\d\.]+)", block)
        defaultinfo_m = re.search(r"set default-information-originate (\S+)", block)
        abr_m = re.search(r"set abr-type (\S+)", block)
        auto_cost_m = re.search(r"set auto-cost-ref-bandwidth (\d+)", block)
        areas = []
        area_sub = self._extract_sub_block(block, "area")
        if area_sub:
            for entry in re.findall(
                r"^\s*edit ([\d\.]+)(.*?)^\s*next", area_sub, re.DOTALL | re.MULTILINE
            ):
                area_id, body = entry
                type_m = re.search(r"set type (\S+)", body)
                areas.append(
                    {
                        "Area ID": area_id,
                        "Type": type_m.group(1).capitalize() if type_m else "Normal",
                    }
                )
        ospf_intfs = []
        oi_sub = self._extract_sub_block(block, "ospf-interface")
        if oi_sub:
            for entry in re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next', oi_sub, re.DOTALL | re.MULTILINE
            ):
                name, body = entry
                intf_m = re.search(r'set interface "([^"]+)"', body)
                area_m = re.search(r"set area ([\d\.]+)", body)
                cost_m = re.search(r"set cost (\d+)", body)
                hello_m = re.search(r"set hello-interval (\d+)", body)
                dead_m = re.search(r"set dead-interval (\d+)", body)
                ospf_intfs.append(
                    {
                        "Name": name,
                        "Interface": intf_m.group(1) if intf_m else "-",
                        "Area": area_m.group(1) if area_m else "-",
                        "Cost": cost_m.group(1) if cost_m else "-",
                        "Hello Interval": hello_m.group(1) if hello_m else "-",
                        "Dead Interval": dead_m.group(1) if dead_m else "-",
                    }
                )
        networks = []
        net_sub = self._extract_sub_block(block, "network")
        if net_sub:
            for entry in re.findall(
                r"^\s*edit (\d+)(.*?)^\s*next", net_sub, re.DOTALL | re.MULTILINE
            ):
                seq, body = entry
                prefix_m = re.search(r"set prefix ([\d\.]+ [\d\.]+|[\d\.\/]+)", body)
                area_m = re.search(r"set area ([\d\.]+)", body)
                networks.append(
                    {
                        "Seq": seq,
                        "Prefix": prefix_m.group(1) if prefix_m else "-",
                        "Area": area_m.group(1) if area_m else "-",
                    }
                )
        return {
            "router_id": router_id_m.group(1) if router_id_m else "-",
            "default_info": (
                defaultinfo_m.group(1).capitalize() if defaultinfo_m else "-"
            ),
            "abr_type": abr_m.group(1).capitalize() if abr_m else "-",
            "auto_cost": auto_cost_m.group(1) if auto_cost_m else "-",
            "areas": areas,
            "interfaces": ospf_intfs,
            "networks": networks,
        }

    def parse_bgp(self) -> dict:
        block = self._extract_block("router bgp")
        if not block:
            return {}
        as_m = re.search(r"set as (\d+)", block)
        router_id_m = re.search(r"set router-id ([\d\.]+)", block)
        keepalive_m = re.search(r"set keepalive-timer (\d+)", block)
        holdtime_m = re.search(r"set holdtime-timer (\d+)", block)
        neighbors = []
        nb_sub = self._extract_sub_block(block, "neighbor")
        if nb_sub:
            for entry in re.findall(
                r'^\s*edit "?([\d\.]+)"?(.*?)^\s*next', nb_sub, re.DOTALL | re.MULTILINE
            ):
                ip, body = entry
                remote_m = re.search(r"set remote-as (\d+)", body)
                desc_m = re.search(r'set description "([^"]+)"', body)
                shutdown_m = re.search(r"set shutdown (enable|disable)", body)
                soft_m = re.search(r"set soft-reconfiguration (enable|disable)", body)
                neighbors.append(
                    {
                        "Neighbor IP": ip,
                        "Remote AS": remote_m.group(1) if remote_m else "-",
                        "Description": desc_m.group(1) if desc_m else "-",
                        "Soft Reconfig": (
                            soft_m.group(1).capitalize() if soft_m else "-"
                        ),
                        "Shutdown": (
                            shutdown_m.group(1).capitalize()
                            if shutdown_m
                            else "Disable"
                        ),
                    }
                )
        networks = []
        net_sub = self._extract_sub_block(block, "network")
        if net_sub:
            for entry in re.findall(
                r"^\s*edit (\d+)(.*?)^\s*next", net_sub, re.DOTALL | re.MULTILINE
            ):
                seq, body = entry
                prefix_m = re.search(r"set prefix ([\d\.]+ [\d\.]+|[\d\.\/]+)", body)
                networks.append(
                    {"Seq": seq, "Prefix": prefix_m.group(1) if prefix_m else "-"}
                )
        return {
            "local_as": as_m.group(1) if as_m else "-",
            "router_id": router_id_m.group(1) if router_id_m else "-",
            "keepalive": keepalive_m.group(1) if keepalive_m else "-",
            "holdtime": holdtime_m.group(1) if holdtime_m else "-",
            "neighbors": neighbors,
            "networks": networks,
        }

    def parse_routing_objects(self) -> dict:
        prefix_lists = []
        pl_block = self._extract_block("router prefix-list")
        if pl_block:
            for name, body in re.findall(
                r'edit "([^"]+)"(.*?)next', pl_block, re.DOTALL
            ):
                for rule_seq, rule_body in re.findall(
                    r"edit (\d+)(.*?)next", body, re.DOTALL
                ):
                    action_m = re.search(r"set action (permit|deny)", rule_body)
                    prefix_m = re.search(
                        r"set prefix ([\d\.]+ [\d\.]+|[\d\.\/]+|any)", rule_body
                    )
                    ge_m = re.search(r"set ge (\d+)", rule_body)
                    le_m = re.search(r"set le (\d+)", rule_body)
                    prefix_lists.append(
                        {
                            "List Name": name,
                            "Seq": rule_seq,
                            "Action": (
                                action_m.group(1).capitalize() if action_m else "-"
                            ),
                            "Prefix": prefix_m.group(1) if prefix_m else "-",
                            "GE": ge_m.group(1) if ge_m else "-",
                            "LE": le_m.group(1) if le_m else "-",
                        }
                    )
        route_maps = []
        rm_block = self._extract_block("router route-map")
        if rm_block:
            for name, body in re.findall(
                r'edit "([^"]+)"(.*?)next', rm_block, re.DOTALL
            ):
                for rule_seq, rule_body in re.findall(
                    r"edit (\d+)(.*?)next", body, re.DOTALL
                ):
                    action_m = re.search(r"set action (permit|deny)", rule_body)
                    match_m = re.search(r'set match-ip-address "([^"]+)"', rule_body)
                    set_med_m = re.search(r"set set-metric (\d+)", rule_body)
                    set_comm_m = re.search(r'set set-community "([^"]+)"', rule_body)
                    route_maps.append(
                        {
                            "Map Name": name,
                            "Seq": rule_seq,
                            "Action": (
                                action_m.group(1).capitalize() if action_m else "-"
                            ),
                            "Match IP": match_m.group(1) if match_m else "-",
                            "Set MED": set_med_m.group(1) if set_med_m else "-",
                            "Set Community": set_comm_m.group(1) if set_comm_m else "-",
                        }
                    )
        aspath_lists = []
        as_block = self._extract_block("router aspath-list")
        if as_block:
            for name, body in re.findall(
                r'edit "([^"]+)"(.*?)next', as_block, re.DOTALL
            ):
                for rule_seq, rule_body in re.findall(
                    r"edit (\d+)(.*?)next", body, re.DOTALL
                ):
                    action_m = re.search(r"set action (permit|deny)", rule_body)
                    regexp_m = re.search(r'set regexp "([^"]+)"', rule_body)
                    aspath_lists.append(
                        {
                            "List Name": name,
                            "Seq": rule_seq,
                            "Action": (
                                action_m.group(1).capitalize() if action_m else "-"
                            ),
                            "Regexp": regexp_m.group(1) if regexp_m else "-",
                        }
                    )
        return {
            "prefix_lists": prefix_lists,
            "route_maps": route_maps,
            "aspath_lists": aspath_lists,
        }

    def parse_multicast(self) -> dict:
        block = self._extract_block("router multicast")
        if not block:
            return {}
        mode_m = re.search(r"set multicast-routing (enable|disable)", block)
        interfaces = []
        intf_sub = self._extract_sub_block(block, "interface")
        if intf_sub:
            for entry in re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next', intf_sub, re.DOTALL | re.MULTILINE
            ):
                name, body = entry
                ttl_m = re.search(r"set ttl-threshold (\d+)", body)
                pim_m = re.search(r"set pim-mode (\S+)", body)
                hello_m = re.search(r"set hello-interval (\d+)", body)
                dr_m = re.search(r"set dr-priority (\d+)", body)
                interfaces.append(
                    {
                        "Interface": name,
                        "PIM Mode": pim_m.group(1).upper() if pim_m else "-",
                        "Hello Interval": hello_m.group(1) if hello_m else "-",
                        "DR Priority": dr_m.group(1) if dr_m else "-",
                        "TTL Threshold": ttl_m.group(1) if ttl_m else "-",
                    }
                )
        pim_sm = {}
        pim_sub = self._extract_sub_block(block, "pim-sm-global")
        if pim_sub:
            register_m = re.search(r"set register-supression-timer (\d+)", pim_sub)
            rps = []
            for rp_ip, rp_body in re.findall(
                r"edit ([\d\.]+)(.*?)next", pim_sub, re.DOTALL
            ):
                group_m = re.search(r'set group "([^"]+)"', rp_body)
                rps.append(
                    {"RP Address": rp_ip, "Group": group_m.group(1) if group_m else "-"}
                )
            pim_sm = {
                "register_suppression": register_m.group(1) if register_m else "-",
                "rp_list": rps,
            }
        return {
            "enabled": mode_m.group(1).capitalize() if mode_m else "Disable",
            "interfaces": interfaces,
            "pim_sm": pim_sm,
        }

    # ═══════════════════════════════════════════════════════════
    #  INTERFACE NAMES  (Policy Lookup dropdown)
    # ═══════════════════════════════════════════════════════════
    def get_interface_names(self) -> list:
        block = self._extract_block("system interface")
        names = re.findall(r'^\s*edit "([^"]+)"', block, re.MULTILINE) if block else []
        zone_block = self._extract_block("system zone")
        if zone_block:
            names += re.findall(r'^\s*edit "([^"]+)"', zone_block, re.MULTILINE)
        return sorted(set(names))

    # ═══════════════════════════════════════════════════════════
    #  ADDRESS OBJECTS  (Policy Lookup matching)
    # ═══════════════════════════════════════════════════════════
    def get_address_objects(self) -> dict:
        addr_map: dict = {}
        block = self._extract_block("firewall address")
        if block:
            for name, body in re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE
            ):
                nets = []
                subnet_m = re.search(r"set subnet ([\d\.]+)\s+([\d\.]+)", body)
                start_m = re.search(r"set start-ip ([\d\.]+)", body)
                end_m = re.search(r"set end-ip ([\d\.]+)", body)
                fqdn_m = re.search(r'set fqdn "([^"]+)"', body)
                if subnet_m:
                    try:
                        nets.append(
                            ipaddress.IPv4Network(
                                f"{subnet_m.group(1)}/{subnet_m.group(2)}", strict=False
                            )
                        )
                    except ValueError:
                        pass
                elif start_m and end_m:
                    try:
                        nets.append(
                            (
                                int(ipaddress.IPv4Address(start_m.group(1))),
                                int(ipaddress.IPv4Address(end_m.group(1))),
                            )
                        )
                    except ValueError:
                        pass
                elif fqdn_m:
                    nets.append(fqdn_m.group(1))
                addr_map[name] = nets
        grp_block = self._extract_block("firewall addrgrp")
        if grp_block:
            for name, body in re.findall(
                r'^\s*edit "([^"]+)"(.*?)^\s*next', grp_block, re.DOTALL | re.MULTILINE
            ):
                member_m = re.search(r"set member (.*)", body)
                if member_m:
                    addr_map[name] = re.findall(r'"([^"]+)"', member_m.group(1))
        return addr_map

    def resolve_address(self, name: str, addr_map: dict, _depth: int = 0) -> list:
        if name.lower() in ("all", "any", ""):
            return []
        if _depth > 10:
            return []
        resolved = []
        for obj in addr_map.get(name, []):
            if isinstance(obj, (ipaddress.IPv4Network, tuple)):
                resolved.append(obj)
            elif isinstance(obj, str):
                sub = self.resolve_address(obj, addr_map, _depth + 1)
                resolved.extend(sub) if sub else resolved.append(obj)
        return resolved

    # ═══════════════════════════════════════════════════════════
    #  LOG SETTINGS
    # ═══════════════════════════════════════════════════════════
    def parse_log_settings(self) -> dict:
        block = self._extract_block("log setting")
        mem_block = self._extract_block("log memory setting")
        sys_block = self._extract_block("log null-device setting")

        def g(b: str, pattern: str, default: str = "disable") -> str:
            m = re.search(pattern, b)
            return m.group(1) if m else default

        return {
            "uuid_traffic": g(block, r"set fwpolicy-implicit-log (\S+)"),
            "address_logging": g(block, r"set local-in-allow (\S+)"),
            "event_logging": g(block, r"set local-in-deny-unicast (\S+)"),
            "local_traffic": g(block, r"set local-in-deny-broadcast (\S+)"),
            "memory": g(mem_block, r"set status (\S+)", "enable"),
            "syslog": g(sys_block, r"set status (\S+)", "disable"),
            "resolve_hosts": g(block, r"set resolve-ip (\S+)", "enable"),
            "resolve_apps": g(block, r"set resolve-port (\S+)", "enable"),
        }

    # ═══════════════════════════════════════════════════════════
    #  THREAT WEIGHT
    # ═══════════════════════════════════════════════════════════
    _WEB_CAT_NAMES = {
        "1": "Drug Abuse",
        "3": "Hacking",
        "4": "Illegal or Unethical",
        "5": "Discrimination",
        "6": "Explicit Violence",
        "12": "Extremist Groups",
        "14": "Proxy Avoidance",
        "26": "Plagiarism",
        "59": "Child Sexual Abuse",
        "61": "Peer-to-peer File Sharing",
        "62": "Pornography",
        "72": "Terrorism",
        "83": "Phishing",
        "86": "Spam URLs",
        "96": "Malicious Websites",
    }
    _APP_CAT_NAMES = {"2": "P2P", "6": "Proxy"}

    def parse_threat_weight(self) -> dict:
        block = self._extract_block("log threat-weight")
        if not block:
            return {}
        _LEVELS = {
            "off": "Off",
            "low": "Low",
            "medium": "Medium",
            "high": "High",
            "critical": "Critical",
        }

        def norm(x):
            return _LEVELS.get((x or "").lower().strip(), "Off")

        def extract_section(section_name, name_map):
            sub = self._extract_sub_block(block, section_name)
            if not sub:
                return {}
            result = {}
            for edit_body in re.findall(r"edit \d+(.*?)next", sub, re.DOTALL):
                cat_m = re.search(r"set category (\d+)", edit_body)
                level_m = re.search(r"set level (\w+)", edit_body)
                if cat_m:
                    cat_label = name_map.get(
                        cat_m.group(1), f"Category {cat_m.group(1)}"
                    )
                    result[cat_label] = norm(level_m.group(1)) if level_m else "Off"
            return result

        status_m = re.search(r"set status (\S+)", block)
        return {
            "status": status_m.group(1) if status_m else "enable",
            "web": extract_section("web", self._WEB_CAT_NAMES),
            "application": extract_section("application", self._APP_CAT_NAMES),
        }
