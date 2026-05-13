"""Palo Alto Policy parsers."""

from parsers.paloalto import (
    PaloAltoParser,
    _members_el,
    _is_disabled,
    _addr_with_negate,
)


def _profile_info(entry) -> dict:
    ps = entry.find("profile-setting")
    if ps is None:
        return {"type": "None", "display": "None"}
    group = ps.find("group/member")
    if group is not None and group.text:
        return {"type": "Group", "display": group.text}
    profiles = ps.find("profiles")
    if profiles is not None:
        parts = {}
        for tag in [
            "virus",
            "spyware",
            "vulnerability",
            "url-filtering",
            "file-blocking",
            "data-filtering",
            "wildfire-analysis",
        ]:
            m = profiles.find(f"{tag}/member")
            parts[tag.replace("-", " ").title()] = (
                m.text if m is not None and m.text else "None"
            )
        return {
            "type": "Profiles",
            "display": " | ".join(f"{k}: {v}" for k, v in parts.items()),
            "detail": parts,
        }
    return {"type": "None", "display": "None"}


class PaloPoliciesParser(PaloAltoParser):

    def _is_panorama_rule(self, entry) -> bool:
        return entry.get("loc") is not None

    def get_security_rules(self) -> list:
        rules_el = self.rb.find("security/rules") if self.rb is not None else None
        if rules_el is None:
            return []
        rows = []
        for entry in rules_el.findall("entry"):
            prof = _profile_info(entry)
            rows.append(
                {
                    "Name": entry.get("name", "-"),
                    "Tags": _members_el(entry.find("tag"), "None"),
                    "Type": entry.findtext("rule-type") or "universal",
                    "Source Zone": _members_el(entry.find("from")),
                    "Source Addr": _addr_with_negate(entry, "source", "negate-source"),
                    "Dest Zone": _members_el(entry.find("to")),
                    "Dest Addr": _addr_with_negate(
                        entry, "destination", "negate-destination"
                    ),
                    "Application": _members_el(entry.find("application")),
                    "Service": _members_el(entry.find("service")),
                    "URL Category": _members_el(entry.find("category")),
                    "Profile Type": prof["type"],
                    "Profile": prof["display"],
                    "Action": entry.findtext("action") or "allow",
                    "_disabled": _is_disabled(entry),
                    "_panorama": self._is_panorama_rule(entry),
                }
            )
        return rows

    def get_nat_rules(self) -> list:
        rules_el = self.rb.find("nat/rules") if self.rb is not None else None
        if rules_el is None:
            return []
        rows = []
        for entry in rules_el.findall("entry"):
            st = entry.find("source-translation")
            src_trans = "None"
            if st is not None:
                dip = st.find("dynamic-ip-and-port")
                dip_only = st.find("dynamic-ip")
                sip = st.find("static-ip")
                if dip is not None:
                    ia = dip.find("interface-address")
                    if ia is not None:
                        src_trans = f"Dyn IP+Port | Intf: {_members_el(ia.find('interface') if ia.find('interface') is not None else None, ia.findtext('interface','-'))} | IP: {ia.findtext('ip','-')}"
                    else:
                        pool = _members_el(dip.find("translated-address"), "-")
                        src_trans = f"Dyn IP+Port | Pool: {pool}"
                elif dip_only is not None:
                    pool = _members_el(dip_only.find("translated-address"), "-")
                    src_trans = f"Dynamic IP | Pool: {pool}"
                elif sip is not None:
                    addr = sip.findtext("translated-address", "-")
                    bidir = sip.findtext("bi-directional", "no")
                    src_trans = f"Static IP: {addr} | Bi-dir: {bidir}"

            dt = entry.find("destination-translation")
            dst_trans = "None"
            if dt is not None:
                ip = dt.findtext("translated-address", "-")
                port = dt.findtext("translated-port", "")
                dst_trans = f"Static: {ip}" + (f":{port}" if port else "")

            rows.append(
                {
                    "Name": entry.get("name", "-"),
                    "Tags": _members_el(entry.find("tag"), "None"),
                    "Source Zone": _members_el(entry.find("from")),
                    "Dest Zone": _members_el(entry.find("to")),
                    "Dest Interface": entry.findtext("to-interface") or "any",
                    "Source Addr": _addr_with_negate(entry, "source", "negate-source"),
                    "Dest Addr": _addr_with_negate(
                        entry, "destination", "negate-destination"
                    ),
                    "Service": entry.findtext("service") or "any",
                    "Src Translation": src_trans,
                    "Dst Translation": dst_trans,
                    "_disabled": _is_disabled(entry),
                    "_panorama": self._is_panorama_rule(entry),
                }
            )
        return rows

    def get_qos_rules(self) -> list:
        rules_el = self.rb.find("qos/rules") if self.rb is not None else None
        if rules_el is None:
            return []
        rows = []
        for entry in rules_el.findall("entry"):
            dscp_el = entry.find("dscp-tos")
            dscp = (
                "any"
                if (dscp_el is not None and dscp_el.find("any") is not None)
                else "codepoints"
            )
            rows.append(
                {
                    "Name": entry.get("name", "-"),
                    "Tags": _members_el(entry.find("tag"), "None"),
                    "Source Zone": _members_el(entry.find("from")),
                    "Source Addr": _members_el(entry.find("source")),
                    "Source User": _members_el(entry.find("source-user")),
                    "Src Device": _members_el(entry.find("source-hip")),
                    "Dest Zone": _members_el(entry.find("to")),
                    "Dest Addr": _members_el(entry.find("destination")),
                    "Dst Device": _members_el(entry.find("destination-hip")),
                    "Application": _members_el(entry.find("application")),
                    "Service": _members_el(entry.find("service")),
                    "DSCP/TOS": dscp,
                    "Class": entry.findtext("action/class") or "any",
                    "Schedule": entry.findtext("schedule") or "any",
                    "_disabled": _is_disabled(entry),
                    "_panorama": self._is_panorama_rule(entry),
                }
            )
        return rows

    def get_pbf_rules(self) -> list:
        rules_el = self.rb.find("pbf/rules") if self.rb is not None else None
        if rules_el is None:
            return []
        rows = []
        for entry in rules_el.findall("entry"):
            from_el = entry.find("from")
            src_zone_intf = "any"
            if from_el is not None:
                zones = [m.text for m in from_el.findall("zone/member") if m.text]
                intfs = [m.text for m in from_el.findall("interface/member") if m.text]
                src_zone_intf = ", ".join(zones or intfs) if (zones or intfs) else "any"

            action_el = entry.find("action")
            action, egress, nexthop, disable_unreach = "no-pbf", "-", "", "-"
            if action_el is not None:
                if action_el.find("no-pbf") is not None:
                    action = "no-pbf"
                elif action_el.find("discard") is not None:
                    action = "discard"
                elif action_el.find("forward") is not None:
                    fwd = action_el.find("forward")
                    action = "forward"
                    egress = fwd.findtext("egress-interface", "-")
                    nexthop = (
                        fwd.findtext("nexthop/ip-address")
                        or fwd.findtext("nexthop/fqdn")
                        or ""
                    )
                    disable_unreach = fwd.findtext(
                        "monitor/disable-if-unreachable", "no"
                    )

            rows.append(
                {
                    "Name": entry.get("name", "-"),
                    "Tags": _members_el(entry.find("tag"), "None"),
                    "Src Zone/Intf": src_zone_intf,
                    "Source Addr": _addr_with_negate(entry, "source", "negate-source"),
                    "Source User": _members_el(entry.find("source-user")),
                    "Dest Addr": _addr_with_negate(
                        entry, "destination", "negate-destination"
                    ),
                    "Application": _members_el(entry.find("application")),
                    "Service": _members_el(entry.find("service")),
                    "Action": action,
                    "Egress I/F": egress,
                    "Next Hop": nexthop,
                    "Sym Return": entry.findtext(
                        "enforce-symmetric-return/enabled", "no"
                    ).capitalize(),
                    "Profile": entry.findtext("profile") or "None",
                    "Target": entry.findtext("target") or "None",
                    "Disable Unreach": disable_unreach.capitalize(),
                    "Schedule": entry.findtext("schedule") or "None",
                    "_disabled": _is_disabled(entry),
                    "_panorama": self._is_panorama_rule(entry),
                }
            )
        return rows

    def get_decryption_rules(self) -> list:
        rules_el = self.rb.find("decryption/rules") if self.rb is not None else None
        if rules_el is None:
            return []
        rows = []
        for entry in rules_el.findall("entry"):
            rows.append(
                {
                    "Name": entry.get("name", "-"),
                    "Tags": _members_el(entry.find("tag"), "None"),
                    "Source Zone": _members_el(entry.find("from")),
                    "Source Addr": _members_el(entry.find("source")),
                    "Source User": _members_el(entry.find("source-user")),
                    "Dest Zone": _members_el(entry.find("to")),
                    "Dest Addr": _members_el(entry.find("destination")),
                    "Dest Device": _members_el(entry.find("destination-hip")),
                    "URL Category": _members_el(entry.find("category")),
                    "Service": _members_el(entry.find("service")),
                    "Action": entry.findtext("action") or "no-decrypt",
                    "Type": entry.findtext("type") or "ssl-forward-proxy",
                    "Decrypt Profile": entry.findtext("profile") or "None",
                    "Log SSL OK": entry.findtext("log-success") or "any",
                    "Log SSL Fail": entry.findtext("log-fail") or "any",
                    "_disabled": _is_disabled(entry),
                    "_panorama": self._is_panorama_rule(entry),
                }
            )
        return rows

    def get_tunnel_inspection_rules(self) -> list:
        rules_el = (
            self.rb.find("tunnel-inspection/rules") if self.rb is not None else None
        )
        if rules_el is None:
            return []
        rows = []
        for entry in rules_el.findall("entry"):
            rows.append(
                {
                    "Name": entry.get("name", "-"),
                    "Tags": _members_el(entry.find("tag"), "None"),
                    "Source Zone": _members_el(entry.find("from")),
                    "Source Addr": _members_el(entry.find("source")),
                    "Source User": _members_el(entry.find("source-user")),
                    "Dest Zone": _members_el(entry.find("to")),
                    "Dest Addr": _members_el(entry.find("destination")),
                    "Protocols": entry.findtext("protocol") or "any",
                    "_disabled": _is_disabled(entry),
                    "_panorama": self._is_panorama_rule(entry),
                }
            )
        return rows

    def get_app_override_rules(self) -> list:
        rules_el = (
            self.rb.find("application-override/rules") if self.rb is not None else None
        )
        if rules_el is None:
            return []
        rows = []
        for entry in rules_el.findall("entry"):
            rows.append(
                {
                    "Name": entry.get("name", "-"),
                    "Tags": _members_el(entry.find("tag"), "None"),
                    "Source Zone": _members_el(entry.find("from")),
                    "Source Addr": _members_el(entry.find("source")),
                    "Dest Zone": _members_el(entry.find("to")),
                    "Dest Addr": _members_el(entry.find("destination")),
                    "Protocol": entry.findtext("protocol") or "any",
                    "Port": entry.findtext("port") or "any",
                    "Application": entry.findtext("application") or "any",
                    "_disabled": _is_disabled(entry),
                    "_panorama": self._is_panorama_rule(entry),
                }
            )
        return rows

    def get_auth_rules(self) -> list:
        rules_el = self.rb.find("authentication/rules") if self.rb is not None else None
        if rules_el is None:
            return []
        rows = []
        for entry in rules_el.findall("entry"):
            rows.append(
                {
                    "Name": entry.get("name", "-"),
                    "Tags": _members_el(entry.find("tag"), "None"),
                    "Source Zone": _members_el(entry.find("from")),
                    "Source Addr": _members_el(entry.find("source")),
                    "Source User": _members_el(entry.find("source-user")),
                    "Dest Zone": _members_el(entry.find("to")),
                    "Dest Addr": _members_el(entry.find("destination")),
                    "Dest Device": _members_el(entry.find("destination-hip")),
                    "Service": _members_el(entry.find("service")),
                    "Auth Enforcement": entry.findtext("action") or "None",
                    "Bypass Proxy": entry.findtext("bypass-web-proxy") or "None",
                    "Log Settings": entry.findtext("log-setting") or "None",
                    "_disabled": _is_disabled(entry),
                    "_panorama": self._is_panorama_rule(entry),
                }
            )
        return rows

    def get_dos_rules(self) -> list:
        rules_el = self.rb.find("dos-protection/rules") if self.rb is not None else None
        if rules_el is None:
            return []
        rows = []
        for entry in rules_el.findall("entry"):

            def _zone_from_el(el):
                if el is None:
                    return "any"
                z = [m.text for m in el.findall("zone/member") if m.text]
                i = [m.text for m in el.findall("interface/member") if m.text]
                return ", ".join(z or i) if (z or i) else "any"

            agg = entry.findtext("aggregate-profile") or "None"
            cl_el = entry.find("classified-profile")
            classified = ""
            if cl_el is not None:
                cp = cl_el.findtext("profile") or ""
                ca = cl_el.findtext("address") or ""
                classified = f"Profile: {cp} | Addr: {ca}"

            rows.append(
                {
                    "Name": entry.get("name", "-"),
                    "Tags": _members_el(entry.find("tag"), "None"),
                    "Src Zone": _zone_from_el(entry.find("from")),
                    "Source Addr": _members_el(entry.find("source")),
                    "Source User": _members_el(entry.find("source-user")),
                    "Dest Addr": _members_el(entry.find("destination")),
                    "Dst Zone": _zone_from_el(entry.find("to")),
                    "Service": _members_el(entry.find("service")),
                    "Action": entry.findtext("action") or "allow",
                    "Aggregate": agg,
                    "Classified": classified or "-",
                    "_disabled": _is_disabled(entry),
                    "_panorama": self._is_panorama_rule(entry),
                }
            )
        return rows

    def get_sdwan_rules(self) -> list:
        rules_el = self.rb.find("sdwan/rules") if self.rb is not None else None
        if rules_el is None:
            return []
        rows = []
        for entry in rules_el.findall("entry"):
            rows.append(
                {
                    "Name": entry.get("name", "-"),
                    "Tags": _members_el(entry.find("tag"), "None"),
                    "Source Zone": _members_el(entry.find("from")),
                    "Source Addr": _members_el(entry.find("source")),
                    "Source User": _members_el(entry.find("source-user")),
                    "Dest Zone": _members_el(entry.find("to")),
                    "Dest Addr": _members_el(entry.find("destination")),
                    "Application": _members_el(entry.find("application")),
                    "Service": _members_el(entry.find("service")),
                    "Traffic Dist": entry.findtext(
                        "action/traffic-distribution-profile"
                    )
                    or "any",
                    "Path Quality": entry.findtext("path-quality-profile") or "any",
                    "SaaS Quality": entry.findtext("saas-quality-profile") or "None",
                    "Error Correction": entry.findtext("error-correction-profile")
                    or "None",
                    "_disabled": _is_disabled(entry),
                    "_panorama": self._is_panorama_rule(entry),
                }
            )
        return rows

    def test_policy_match(
        self,
        policy_type: str,
        src_zone: str,
        dst_zone: str,
        src_intf: str,
        dst_intf: str,
        src_ip: str,
        dst_ip: str,
        dst_port: str,
        src_user: str = "any",
        protocol: str = "tcp",
    ) -> dict:
        """
        Evaluates rules from TOP to BOTTOM.
        Enforces AND condition across all 9 criteria.
        """
        rules_el = None
        if self.rb is not None:
            type_map = {
                "security": "security/rules",
                "nat": "nat/rules",
                "qos": "qos/rules",
                "pbf": "pbf/rules",
                "decryption": "decryption/rules",
                "auth": "authentication/rules",
                "dos": "dos-protection/rules",
            }
            path = type_map.get(policy_type)
            if path:
                rules_el = self.rb.find(path)

        if rules_el is None:
            return {
                "matched": False,
                "rule": None,
                "action": "deny",
                "reason": "No rulebase found.",
            }

        addr_map, group_map = self._build_addr_map(), self._build_group_map()
        svc_map, svc_grp_map = self._build_svc_map(), self._build_svc_group_map()

        for idx, entry in enumerate(rules_el.findall("entry")):
            if (entry.findtext("disabled") or "no").lower() == "yes":
                continue

            # --- START AND CONDITION EVALUATION ---

            # 1 & 2. Zones
            from_z = [m.text for m in entry.findall("from/member") if m.text]
            to_z = [m.text for m in entry.findall("to/member") if m.text]
            sz_ok = (
                not src_zone
                or src_zone.lower() == "any"
                or "any" in [z.lower() for z in from_z]
                or src_zone in from_z
            )
            dz_ok = (
                not dst_zone
                or dst_zone.lower() == "any"
                or "any" in [z.lower() for z in to_z]
                or dst_zone in to_z
            )
            if not (sz_ok and dz_ok):
                continue

            # 3 & 4. Interfaces (Specific to PBF or specific rule types)
            # Note: Security rules often use zones, but we check interface members if present
            from_i = [m.text for m in entry.findall("from/interface/member") if m.text]
            to_i = [m.text for m in entry.findall("to/interface/member") if m.text]
            si_ok = (
                not src_intf
                or src_intf.lower() == "any"
                or not from_i
                or src_intf in from_i
            )
            di_ok = (
                not dst_intf
                or dst_intf.lower() == "any"
                or not to_i
                or dst_intf in to_i
            )
            if not (si_ok and di_ok):
                continue

            # 5 & 6. IPs
            src_m = [m.text for m in entry.findall("source/member") if m.text]
            dst_m = [m.text for m in entry.findall("destination/member") if m.text]
            if not self._ip_matches_members(src_ip, src_m, addr_map, group_map):
                continue
            if not self._ip_matches_members(dst_ip, dst_m, addr_map, group_map):
                continue

            # 7. Source User
            user_m = [m.text for m in entry.findall("source-user/member") if m.text]
            user_ok = (
                src_user.lower() == "any"
                or "any" in [u.lower() for u in user_m]
                or not user_m
                or src_user in user_m
            )
            if not user_ok:
                continue

            # 8 & 9. Port and Protocol
            svc_m = [m.text for m in entry.findall("service/member") if m.text] or [
                "any"
            ]
            if not self._svc_matches_members(
                dst_port, protocol, svc_m, svc_map, svc_grp_map
            ):
                continue

            # --- ALL CRITERIA MET (MATCH FOUND) ---
            action = entry.findtext("action") or "allow"
            return {
                "matched": True,
                "rule": {
                    "Name": entry.get("name"),
                    "Order": idx + 1,
                    "Action": action.upper(),
                    "Source": f"{src_zone} / {src_ip}",
                    "Destination": f"{dst_zone} / {dst_ip}",
                },
                "action": action,
                "reason": f"Hit Policy: {entry.get('name')} (Index {idx+1})",
            }

        return {
            "matched": False,
            "rule": None,
            "action": "deny",
            "reason": "Implicit Default Deny",
        }

    # ── IP / Port helpers ─────────────────────────────────────
    def _build_addr_map(self):
        """Return dict {name: [(type, value), ...]} for all address objects."""
        addr_map = {}
        addr_el = self.vsys.find("address") if self.vsys is not None else None
        if addr_el is None:
            return addr_map
        for e in addr_el.findall("entry"):
            name = e.get("name", "")
            entries = []
            for t in ["ip-netmask", "ip-range", "fqdn", "ip-wildcard"]:
                el = e.find(t)
                if el is not None and el.text:
                    entries.append((t, el.text.strip()))
                    break
            if entries:
                addr_map[name] = entries
        return addr_map

    def _build_group_map(self):
        """Return dict {name: [member_names, ...]} for address groups."""
        group_map = {}
        el = self.vsys.find("address-group") if self.vsys is not None else None
        if el is None:
            return group_map
        for e in el.findall("entry"):
            static = e.find("static")
            if static is not None:
                members = [m.text for m in static.findall("member") if m.text]
                group_map[e.get("name", "")] = members
        return group_map

    def _build_svc_map(self):
        """Return dict {name: [(proto, port_spec), ...]} for service objects."""
        svc_map = {}
        el = self.vsys.find("service") if self.vsys is not None else None
        if el is None:
            return svc_map
        for e in el.findall("entry"):
            name = e.get("name", "")
            entries = []
            for proto in ["tcp", "udp"]:
                p = e.find(f"protocol/{proto}/port")
                if p is not None and p.text:
                    entries.append((proto, p.text.strip()))
            if entries:
                svc_map[name] = entries
        return svc_map

    def _build_svc_group_map(self):
        """Return dict {name: [member_names]} for service groups."""
        grp_map = {}
        el = self.vsys.find("service-group") if self.vsys is not None else None
        if el is None:
            return grp_map
        for e in el.findall("entry"):
            members = [m.text for m in e.findall("members/member") if m.text]
            grp_map[e.get("name", "")] = members
        return grp_map

    @staticmethod
    def _ip_in_cidr(ip_str: str, cidr: str) -> bool:
        import ipaddress

        try:
            ip = ipaddress.ip_address(ip_str.strip())
            net = ipaddress.ip_network(cidr.strip(), strict=False)
            return ip in net
        except Exception:
            return False

    @staticmethod
    def _ip_in_range(ip_str: str, range_str: str) -> bool:
        import ipaddress

        try:
            ip = ipaddress.ip_address(ip_str.strip())
            parts = range_str.strip().split("-")
            if len(parts) != 2:
                return False
            start = ipaddress.ip_address(parts[0].strip())
            end = ipaddress.ip_address(parts[1].strip())
            return start <= ip <= end
        except Exception:
            return False

    @staticmethod
    def _port_in_spec(port: str, spec: str) -> bool:
        try:
            p = int(port.strip())
        except:
            return False
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    lo, hi = part.split("-", 1)
                    if int(lo) <= p <= int(hi):
                        return True
                except:
                    pass
            else:
                try:
                    if int(part) == p:
                        return True
                except:
                    pass
        return False

    def _resolve_addr(
        self, name: str, addr_map: dict, group_map: dict, visited=None
    ) -> list:
        if visited is None:
            visited = set()
        if name in visited:
            return []
        visited.add(name)
        if name in addr_map:
            return [
                ("range" if t == "ip-range" else "fqdn" if t == "fqdn" else "cidr", v)
                for t, v in addr_map[name]
            ]
        if name in group_map:
            results = []
            for member in group_map[name]:
                results.extend(self._resolve_addr(member, addr_map, group_map, visited))
            return results
        if "/" in name or name.replace(".", "").isdigit():
            return [("cidr", name)]
        return []

    def _ip_matches_members(
        self, ip: str, members: list, addr_map: dict, group_map: dict
    ) -> bool:
        if not ip or ip.lower() in ("any", ""):
            return True
        if not members:
            return True
        for m in members:
            if m.lower() == "any":
                return True
            for atype, aval in self._resolve_addr(m, addr_map, group_map):
                if atype == "cidr" and self._ip_in_cidr(ip, aval):
                    return True
                elif atype == "range" and self._ip_in_range(ip, aval):
                    return True
                elif atype == "fqdn" and (ip.lower() in aval.lower()):
                    return True
        return False

    def _svc_matches_members(
        self,
        dst_port: str,
        protocol: str,
        svc_members: list,
        svc_map: dict,
        svc_grp_map: dict,
    ) -> bool:
        if not dst_port or dst_port.lower() == "any":
            return True
        for svc_name in svc_members:
            if svc_name.lower() in ("any", "application-default"):
                return True
            if svc_name in svc_map:
                for proto, port_spec in svc_map[svc_name]:
                    if protocol.lower() == "any" or proto.lower() == protocol.lower():
                        if self._port_in_spec(dst_port, port_spec):
                            return True
            elif svc_name in svc_grp_map:
                if self._svc_matches_members(
                    dst_port, protocol, svc_grp_map[svc_name], svc_map, svc_grp_map
                ):
                    return True
        return False

    def test_policy_match(
        self,
        policy_type: str,
        src_zone: str,
        dst_zone: str,
        src_intf: str,
        dst_intf: str,
        src_ip: str,
        dst_ip: str,
        src_user: str,
        dst_port: str,
        protocol: str,
    ) -> dict:
        """
        Evaluates rules from TOP to BOTTOM.
        Returns the FIRST rule where ALL 9 criteria match (AND condition).
        """
        rules_el = None
        if self.rb is not None:
            type_map = {
                "security": "security/rules",
                "nat": "nat/rules",
                "qos": "qos/rules",
                "pbf": "pbf/rules",
                "decryption": "decryption/rules",
                "auth": "authentication/rules",
                "dos": "dos-protection/rules",
            }
            path = type_map.get(policy_type)
            if path:
                rules_el = self.rb.find(path)

        if rules_el is None:
            return {
                "matched": False,
                "rule": None,
                "action": "deny",
                "reason": "No rulebase found.",
            }

        addr_map, group_map = self._build_addr_map(), self._build_group_map()
        svc_map, svc_grp_map = self._build_svc_map(), self._build_svc_group_map()

        # Rules are ordered in XML from highest priority (top) to lowest (bottom)
        for idx, entry in enumerate(rules_el.findall("entry")):
            if (entry.findtext("disabled") or "no").lower() == "yes":
                continue

            # --- START 9-CRITERIA AND CHECK ---

            # 1 & 2. Zones (Source & Destination)
            from_z = [m.text for m in entry.findall("from/member") if m.text]
            to_z = [m.text for m in entry.findall("to/member") if m.text]
            sz_ok = (
                not src_zone
                or src_zone.lower() == "any"
                or "any" in [z.lower() for z in from_z]
                or src_zone in from_z
            )
            dz_ok = (
                not dst_zone
                or dst_zone.lower() == "any"
                or "any" in [z.lower() for z in to_z]
                or dst_zone in to_z
            )
            if not (sz_ok and dz_ok):
                continue

            # 3 & 4. Interfaces (Source & Destination)
            from_i = [m.text for m in entry.findall("from/interface/member") if m.text]
            to_i = [m.text for m in entry.findall("to/interface/member") if m.text]
            si_ok = (
                not src_intf
                or src_intf.lower() == "any"
                or not from_i
                or "any" in from_i
                or src_intf in from_i
            )
            di_ok = (
                not dst_intf
                or dst_intf.lower() == "any"
                or not to_i
                or "any" in to_i
                or dst_intf in to_i
            )
            if not (si_ok and di_ok):
                continue

            # 5 & 6. IPs (Source & Destination)
            src_m = [m.text for m in entry.findall("source/member") if m.text]
            dst_m = [m.text for m in entry.findall("destination/member") if m.text]
            if not self._ip_matches_members(src_ip, src_m, addr_map, group_map):
                continue
            if not self._ip_matches_members(dst_ip, dst_m, addr_map, group_map):
                continue

            # 7. Source User
            user_m = [m.text for m in entry.findall("source-user/member") if m.text]
            user_ok = (
                src_user.lower() == "any"
                or not user_m
                or "any" in [u.lower() for u in user_m]
                or src_user in user_m
            )
            if not user_ok:
                continue

            # 8 & 9. Destination Port & Protocol
            svc_m = [m.text for m in entry.findall("service/member") if m.text] or [
                "any"
            ]
            if not self._svc_matches_members(
                dst_port, protocol, svc_m, svc_map, svc_grp_map
            ):
                continue

            # --- MATCH SUCCESS ---
            # If we reach here, all 9 criteria are TRUE for this specific rule.
            action = entry.findtext("action") or "allow"
            return {
                "matched": True,
                "rule": {
                    "Rule Name": entry.get("name"),
                    "Priority (Index)": idx + 1,
                    "Action": action.upper(),
                },
                "action": action,
                "reason": f"Hit Policy: {entry.get('name')} at Index {idx+1}",
            }

        # If the loop finishes without a match, return the default behavior
        return {
            "matched": False,
            "rule": None,
            "action": "deny",
            "reason": "No policy matched all criteria. Traffic hits Implicit Default Deny.",
        }
