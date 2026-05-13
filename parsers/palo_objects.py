"""Palo Alto Objects parsers - extended."""
from parsers.paloalto import PaloAltoParser, _members_el

PREDEFINED_NAMES = {
    "any", "application-default", "service-http", "service-https",
    "ping", "default", "intrazone-default", "interzone-default",
}


def _is_predefined(name: str) -> bool:
    return name.lower() in PREDEFINED_NAMES or name.lower().startswith("predefined")


def _action_from_el(el) -> str:
    if el is None:
        return "default"
    for action in ["reset-both","reset-client","reset-server","drop","allow","alert","block-ip"]:
        if el.find(action) is not None:
            return action
    return el.text or "default"


class PaloObjectsParser(PaloAltoParser):

    # ── helpers ────────────────────────────────────────────────────
    def _shared(self):
        return self.root.find("shared") if self.root is not None else None

    def _vsys_profiles(self):
        return self.vsys.find("profiles") if self.vsys is not None else None

    def _shared_profiles(self):
        s = self._shared()
        return s.find("profiles") if s is not None else None

    def _find_profiles(self, tag):
        """Return list of profile entries from both vsys and shared."""
        entries = []
        for el in [self._vsys_profiles(), self._shared_profiles()]:
            if el is not None:
                pt = el.find(tag)
                if pt is not None:
                    entries += list(pt.findall("entry"))
        return entries

    # ── ADDRESSES ──────────────────────────────────────────────────
    def get_addresses(self) -> list:
        addr_el = self.vsys.find("address") if self.vsys is not None else None
        if addr_el is None:
            return []
        rows = []
        for entry in addr_el.findall("entry"):
            atype, value = "ip-netmask", "-"
            for t in ["ip-netmask","ip-range","fqdn","ip-wildcard"]:
                el = entry.find(t)
                if el is not None and el.text:
                    atype, value = t, el.text
                    break
            rows.append({
                "Name":        entry.get("name","-"),
                "Type":        atype.replace("-"," ").title(),
                "Value":       value,
                "Description": entry.findtext("description") or "-",
                "Tags":        _members_el(entry.find("tag"),"None"),
            })
        return rows

    def get_address_groups(self) -> list:
        el = self.vsys.find("address-group") if self.vsys is not None else None
        if el is None:
            return []
        rows = []
        for entry in el.findall("entry"):
            static  = entry.find("static")
            dynamic = entry.find("dynamic")
            if static is not None:
                members, gtype = _members_el(static), "Static"
            elif dynamic is not None:
                members, gtype = entry.findtext("dynamic/filter") or "-", "Dynamic"
            else:
                members, gtype = "-", "-"
            rows.append({
                "Name":        entry.get("name","-"),
                "Type":        gtype,
                "Members":     members,
                "Description": entry.findtext("description") or "-",
                "Tags":        _members_el(entry.find("tag"),"None"),
            })
        return rows

    # ── SERVICES (includes predefined) ─────────────────────────────
    def get_services(self) -> list:
        rows = []
        seen = set()

        def _parse_svc_el(el, location):
            if el is None:
                return
            for entry in el.findall("entry"):
                name = entry.get("name","-")
                if name in seen:
                    continue
                seen.add(name)
                proto, ports = "tcp", "-"
                for p in ["tcp","udp","sctp"]:
                    pel = entry.find(f"protocol/{p}/port")
                    if pel is not None and pel.text:
                        proto, ports = p.upper(), pel.text
                        break
                rows.append({
                    "Name":        name,
                    "Location":    location,
                    "Protocol":    proto,
                    "Ports":       ports,
                    "Description": entry.findtext("description") or "-",
                    "Tags":        _members_el(entry.find("tag"),"None"),
                })

        # vsys services
        _parse_svc_el(self.vsys.find("service") if self.vsys else None, "vsys1")
        # shared services
        s = self._shared()
        _parse_svc_el(s.find("service") if s else None, "shared")
        return rows

    def get_service_groups(self) -> list:
        el = self.vsys.find("service-group") if self.vsys is not None else None
        if el is None:
            return []
        rows = []
        for entry in el.findall("entry"):
            rows.append({
                "Name":    entry.get("name","-"),
                "Members": _members_el(entry.find("members")),
                "Tags":    _members_el(entry.find("tag"),"None"),
            })
        return rows

    def get_tags(self) -> list:
        el = self.vsys.find("tag") if self.vsys is not None else None
        if el is None:
            return []
        rows = []
        for entry in el.findall("entry"):
            rows.append({
                "Name":     entry.get("name","-"),
                "Color":    entry.findtext("color") or "-",
                "Comments": entry.findtext("comments") or "-",
            })
        return rows

    # ── REGIONS ────────────────────────────────────────────────────
    def get_regions(self) -> list:
        rows = []
        for src_el, loc in [
            (self.vsys.find("region") if self.vsys else None, "vsys1"),
            (self._shared().find("region") if self._shared() else None, "shared"),
        ]:
            if src_el is None:
                continue
            for entry in src_el.findall("entry"):
                addrs = [m.text for m in entry.findall("address/member") if m.text]
                geo   = entry.find("geo-location")
                rows.append({
                    "Name":      entry.get("name","-"),
                    "Location":  loc,
                    "IP":        ", ".join(addrs) if addrs else "-",
                    "Latitude":  _members_el(geo.find("latitude") if geo else None, "-") if geo is not None else "-",
                    "Longitude": _members_el(geo.find("longitude") if geo else None, "-") if geo is not None else "-",
                })
                # fix: geo children are text not members
                if geo is not None:
                    lat_el = geo.find("latitude")
                    lon_el = geo.find("longitude")
                    rows[-1]["Latitude"]  = lat_el.text if lat_el is not None and lat_el.text else "-"
                    rows[-1]["Longitude"] = lon_el.text if lon_el is not None and lon_el.text else "-"
        return rows

    # ── DYNAMIC USER GROUPS ────────────────────────────────────────
    def get_dynamic_user_groups(self) -> list:
        rows = []
        for src_el, loc in [
            (self.vsys.find("dynamic-user-group") if self.vsys else None, "vsys1"),
            (self._shared().find("dynamic-user-group") if self._shared() else None, "shared"),
        ]:
            if src_el is None:
                continue
            for entry in src_el.findall("entry"):
                rows.append({
                    "Name":        entry.get("name","-"),
                    "Location":    loc,
                    "Filter":      entry.findtext("filter") or "-",
                    "Description": entry.findtext("description") or "-",
                    "Tags":        _members_el(entry.find("tag"),"None"),
                })
        return rows

    # ── DEVICES ────────────────────────────────────────────────────
    def get_devices(self) -> list:
        rows = []
        dev_el = self.vsys.find("devices") if self.vsys else None
        if dev_el is None:
            return []
        for entry in dev_el.findall("entry"):
            rows.append({
                "Name":       entry.get("name","-"),
                "Location":   "vsys1",
                "Category":   entry.findtext("category") or "-",
                "Profile":    entry.findtext("profile") or "-",
                "Model":      entry.findtext("model") or "-",
                "OS Version": entry.findtext("os-version") or "-",
                "OS Family":  entry.findtext("os-family") or "-",
                "Vendor":     entry.findtext("vendor") or "-",
            })
        return rows

    # ── HIP OBJECTS ────────────────────────────────────────────────
    def get_hip_objects(self) -> list:
        hip_el = self.vsys.find("hip-object") if self.vsys else None
        if hip_el is None:
            return []
        rows = []
        for entry in hip_el.findall("entry"):
            # Determine category from sub-elements
            cats = []
            for c in ["host-info","network","patch-management","firewall","antivirus",
                      "anti-malware","disk-encryption","mobile-device","certificate"]:
                if entry.find(c) is not None:
                    cats.append(c.replace("-"," ").title())
            # Criteria summary
            criteria_parts = []
            hi = entry.find("host-info")
            if hi is not None:
                os_el = hi.find("os/contains")
                if os_el is not None and os_el.text:
                    criteria_parts.append(f"OS: {os_el.text}")
            av = entry.find("antivirus")
            if av is not None:
                criteria_parts.append("Antivirus check")
            rows.append({
                "Name":        entry.get("name","-"),
                "Location":    "vsys1",
                "Category":    ", ".join(cats) if cats else "-",
                "Criteria":    " | ".join(criteria_parts) if criteria_parts else "-",
                "Vendor":      entry.findtext("antivirus/entry/vendor") or "-",
                "Description": entry.findtext("description") or "-",
            })
        return rows

    def get_hip_profiles(self) -> list:
        hip_el = self.vsys.find("hip-profile") if self.vsys else None
        if hip_el is None:
            return []
        rows = []
        for entry in hip_el.findall("entry"):
            rows.append({
                "Name":        entry.get("name","-"),
                "Location":    "vsys1",
                "Match":       entry.findtext("match") or "-",
                "Description": entry.findtext("description") or "-",
            })
        return rows

    # ── EXTERNAL DYNAMIC LISTS ─────────────────────────────────────
    def get_external_dynamic_lists(self) -> list:
        PREDEFINED_PREFIXES = ("panw-", "Palo Alto Networks", "predefined")
        rows = []
        for src_el, loc in [
            (self.vsys.find("external-list") if self.vsys else None, "vsys1"),
            (self._shared().find("external-list") if self._shared() else None, "shared"),
        ]:
            if src_el is None:
                continue
            for entry in src_el.findall("entry"):
                name = entry.get("name","-")
                # Skip predefined
                if any(name.lower().startswith(p.lower()) for p in PREDEFINED_PREFIXES):
                    continue
                type_el = entry.find("type")
                etype, desc, url, cert_profile, freq = "-","-","-","-","-"
                if type_el is not None:
                    for t in ["ip","url","domain","imsi","imei","predefined-ip","predefined-url"]:
                        tel = type_el.find(t)
                        if tel is not None:
                            etype        = t.replace("-"," ").title()
                            desc         = tel.findtext("description") or "-"
                            url          = tel.findtext("url") or "-"
                            cert_profile = tel.findtext("certificate-profile") or "-"
                            # Frequency
                            rec = tel.find("recurring")
                            if rec is not None:
                                for f in ["hourly","daily","weekly","monthly","five-minute"]:
                                    if rec.find(f) is not None:
                                        at = rec.findtext(f"{f}/at","")
                                        freq = f.title() + (f" at {at}" if at else "")
                                        break
                            break
                rows.append({
                    "Name":        name,
                    "Location":    loc,
                    "Type":        etype,
                    "Description": desc,
                    "Source":      url,
                    "Cert Profile": cert_profile,
                    "Frequency":   freq,
                })
        return rows

    # ── CUSTOM OBJECTS ─────────────────────────────────────────────
    def get_data_patterns(self) -> list:
        rows = []
        for src_el, loc in [
            (self.vsys.find("data-objects") if self.vsys else None, "vsys1"),
            (self._shared().find("data-objects") if self._shared() else None, "shared"),
        ]:
            if src_el is None:
                continue
            for entry in src_el.findall("entry"):
                pt = entry.find("pattern-type")
                ptype, pname, pattern, default_ft = "-", "-", "-", "-"
                if pt is not None:
                    for t in ["regex","file-properties","predefined-pattern"]:
                        tel = pt.find(t)
                        if tel is not None:
                            ptype = t.replace("-"," ").title()
                            for sub in tel.findall("entry"):
                                pname   = sub.get("name","-")
                                pattern = sub.findtext("regex-string") or sub.findtext("pattern") or "-"
                                default_ft = sub.findtext("file-type") or "-"
                            break
                rows.append({
                    "Profile Name":    entry.get("name","-"),
                    "Location":        loc,
                    "Type":            ptype,
                    "Pattern Name":    pname,
                    "Default File Type": default_ft,
                    "Pattern":         pattern,
                })
        return rows

    def get_custom_spyware(self) -> list:
        rows = []
        for entry in self._find_profiles("spyware"):
            name = entry.get("name","-")
            if _is_predefined(name):
                continue
            for rule in entry.findall("threat-exception/entry") + entry.findall("rules/entry"):
                action_el = rule.find("action") or rule.find("default-action")
                rows.append({
                    "Profile Name":   name,
                    "Threat ID":      rule.findtext("threat-id") or rule.findtext("threat-name") or "any",
                    "Severity":       _members_el(rule.find("severity")),
                    "Direction":      rule.findtext("direction") or "both",
                    "Default Action": _action_from_el(action_el),
                    "Packet Capture": rule.findtext("packet-capture") or "-",
                    "Comment":        rule.findtext("comment") or "-",
                })
        return rows

    def get_custom_vulnerability(self) -> list:
        rows = []
        for entry in self._find_profiles("vulnerability"):
            name = entry.get("name","-")
            if _is_predefined(name):
                continue
            for rule in entry.findall("threat-exception/entry") + entry.findall("rules/entry"):
                action_el = rule.find("action") or rule.find("default-action")
                rows.append({
                    "Profile Name":    name,
                    "Threat ID":       rule.findtext("threat-id") or rule.findtext("threat-name") or "any",
                    "Severity":        _members_el(rule.find("severity")),
                    "Direction":       rule.findtext("direction") or "both",
                    "Default Action":  _action_from_el(action_el),
                    "Affected System": rule.findtext("affected-host") or "any",
                    "Comment":         rule.findtext("comment") or "-",
                })
        return rows

    def get_custom_url_categories(self) -> list:
        el = self.vsys.find("profiles/custom-url-category") if self.vsys else None
        if el is None:
            return []
        rows = []
        for entry in el.findall("entry"):
            members = [m.text for m in entry.findall("list/member") if m.text]
            rows.append({
                "Name":    entry.get("name","-"),
                "Type":    entry.findtext("type") or "URL List",
                "Entries": len(members),
                "Sample":  ", ".join(members[:5]) + ("..." if len(members)>5 else ""),
            })
        return rows

    # ── SECURITY PROFILES (custom only) ────────────────────────────
    def get_av_profiles(self) -> list:
        rows = []
        for entry in self._find_profiles("virus"):
            name = entry.get("name","-")
            if _is_predefined(name):
                continue
            for decoder in entry.findall("decoder/entry"):
                proto = decoder.get("name","-")
                sig_action   = decoder.findtext("action") or "default"
                wf_action    = decoder.findtext("wildfire-action") or "default"
                wf_inline_ml = decoder.findtext("mlav-action") or "default"
                rows.append({
                    "Name":                 name,
                    "Protocol":             proto.upper(),
                    "Signature Action":     sig_action,
                    "WildFire Sig Action":  wf_action,
                    "WildFire Inline ML":   wf_inline_ml,
                })
        return rows

    def get_spyware_profiles(self) -> list:
        rows = []
        for entry in self._find_profiles("spyware"):
            name = entry.get("name","-")
            if _is_predefined(name):
                continue
            rule_list = list(entry.findall("rules/entry")) + list(entry.findall("threat-exception/entry"))
            for rule in rule_list:
                action_el = rule.find("action")
                action_name = "default"
                if action_el is not None:
                    for a in ["reset-both","reset-client","reset-server","drop","allow","alert","block-ip"]:
                        if action_el.find(a) is not None:
                            action_name = a
                            break
                rows.append({
                    "Profile Name":   name,
                    "Count":          len(rule_list),
                    "Rule Name":      rule.get("name","-"),
                    "Threat Name":    rule.findtext("threat-name") or "any",
                    "Severity":       _members_el(rule.find("severity")),
                    "Action":         action_name,
                    "Packet Capture": rule.findtext("packet-capture") or "disable",
                })
        return rows

    def get_vulnerability_profiles(self) -> list:
        rows = []
        for entry in self._find_profiles("vulnerability"):
            name = entry.get("name","-")
            if _is_predefined(name):
                continue
            rule_list = list(entry.findall("rules/entry")) + list(entry.findall("threat-exception/entry"))
            for rule in rule_list:
                action_el = rule.find("action")
                action_name = "default"
                if action_el is not None:
                    for a in ["reset-both","reset-client","reset-server","drop","allow","alert","block-ip"]:
                        if action_el.find(a) is not None:
                            action_name = a
                            break
                rows.append({
                    "Profile Name":   name,
                    "Count":          len(rule_list),
                    "Rule Name":      rule.get("name","-"),
                    "Threat Name":    rule.findtext("threat-name") or "any",
                    "Host Type":      rule.findtext("host") or "any",
                    "Severity":       _members_el(rule.find("severity")),
                    "Action":         action_name,
                    "Packet Capture": rule.findtext("packet-capture") or "disable",
                })
        return rows

    def get_url_filtering_profiles(self) -> list:
        rows = []
        for entry in self._find_profiles("url-filtering"):
            name = entry.get("name","-")
            if _is_predefined(name):
                continue
            # Collect all categories with their actions
            cat_actions = {}
            for action_tag in ["block","alert","allow","continue","override","none"]:
                for m in entry.findall(f"{action_tag}/member"):
                    if m.text:
                        cat_actions[m.text] = action_tag
            cred_actions = {}
            for action_tag in ["block","alert","allow","continue","override","none"]:
                for m in entry.findall(f"credential-enforcement/{action_tag}/member"):
                    if m.text:
                        cred_actions[m.text] = action_tag
            categories = []
            for cat in sorted(set(list(cat_actions.keys()) + list(cred_actions.keys()))):
                categories.append({
                    "Category":     cat,
                    "Site Access":  cat_actions.get(cat, "none"),
                    "Cred Submit":  cred_actions.get(cat, "none"),
                })
            rows.append({
                "name":       name,
                "categories": categories,
            })
        return rows

    def get_file_blocking_profiles(self) -> list:
        rows = []
        for entry in self._find_profiles("file-blocking"):
            name = entry.get("name","-")
            if _is_predefined(name):
                continue
            for rule in entry.findall("rules/entry"):
                rows.append({
                    "Profile Name": name,
                    "Rule Name":    rule.get("name","-"),
                    "Applications": _members_el(rule.find("application")),
                    "File Types":   _members_el(rule.find("file-type")),
                    "Direction":    rule.findtext("direction") or "both",
                    "Action":       rule.findtext("action") or "forward",
                })
        return rows

    def get_wildfire_profiles(self) -> list:
        rows = []
        for entry in self._find_profiles("wildfire-analysis"):
            name = entry.get("name","-")
            if _is_predefined(name):
                continue
            for rule in entry.findall("rules/entry"):
                rows.append({
                    "Profile Name": name,
                    "Rule Name":    rule.get("name","-"),
                    "Applications": _members_el(rule.find("application")),
                    "File Types":   _members_el(rule.find("file-type")),
                    "Direction":    rule.findtext("direction") or "both",
                    "Analysis":     rule.findtext("analysis") or "public-cloud",
                })
        return rows

    def get_data_filtering_profiles(self) -> list:
        rows = []
        for entry in self._find_profiles("data-filtering"):
            name = entry.get("name","-")
            if _is_predefined(name):
                continue
            for rule in entry.findall("rules/entry"):
                rows.append({
                    "Profile Name":    name,
                    "Data Capture":    entry.findtext("data-capture") or "disable",
                    "Data Pattern":    rule.findtext("data-object") or "-",
                    "Applications":    _members_el(rule.find("application")),
                    "File Types":      _members_el(rule.find("file-type")),
                    "Direction":       rule.findtext("direction") or "both",
                    "Alert Threshold": rule.findtext("alert-threshold") or "-",
                    "Block Threshold": rule.findtext("block-threshold") or "-",
                    "Log Severity":    rule.findtext("log-severity") or "-",
                })
        return rows

    def get_dos_protection_profiles(self) -> list:
        rows = []
        for entry in self._find_profiles("dos-protection"):
            name = entry.get("name","-")
            if _is_predefined(name):
                continue
            flood = entry.find("flood")
            sess  = entry.find("resource")

            def _flood_info(tag):
                el = flood.find(tag) if flood is not None else None
                if el is None:
                    return "-"
                en = el.findtext("enable") or "no"
                rate = el.findtext("red") or el.findtext("alarm-rate") or el.findtext("activate-rate") or "-"
                return f"{'On' if en=='yes' else 'Off'} | rate: {rate}"

            rows.append({
                "Name":         name,
                "Type":         entry.findtext("type") or "aggregate",
                "SYN Flood":    _flood_info("tcp-syn"),
                "UDP Flood":    _flood_info("udp"),
                "ICMP Flood":   _flood_info("icmp"),
                "ICMPv6 Flood": _flood_info("icmpv6"),
                "Other IP":     _flood_info("other"),
                "Sessions":     sess.findtext("max-concurrent-limit") if sess is not None else "-",
            })
        return rows

    def get_decryption_profiles(self) -> list:
        rows = []
        for src_el in [self._vsys_profiles(), self._shared_profiles()]:
            if src_el is None:
                continue
            dp = src_el.find("decryption")
            if dp is None:
                continue
            for entry in dp.findall("entry"):
                name = entry.get("name","-")
                if _is_predefined(name):
                    continue
                sfp = entry.find("ssl-forward-proxy")
                sii = entry.find("ssl-inbound-proxy") or entry.find("ssl-inbound-inspection")
                sps = entry.find("ssl-protocol-settings")
                nd  = entry.find("no-decryption")
                ssh = entry.find("ssh-proxy")

                def _yn(el, tag):
                    return (el.findtext(tag) or "no").capitalize() if el is not None else "-"

                rows.append({
                    "Name":               name,
                    # SSL Forward Proxy
                    "SFP - Block Untrusted Issuer":  _yn(sfp,"block-untrusted-issuer"),
                    "SFP - Block Expired Cert":      _yn(sfp,"block-expired-certificate"),
                    "SFP - Block Unknown Status":    _yn(sfp,"block-unknown-cert-status"),
                    "SFP - Block Unsupported Ver":   _yn(sfp,"block-unsupported-version"),
                    "SFP - Block Unsupported Cipher":_yn(sfp,"block-unsupported-cipher"),
                    # SSL Inbound
                    "SII - Block Unsupported Ver":   _yn(sii,"block-unsupported-version"),
                    "SII - Block Unsupported Cipher":_yn(sii,"block-unsupported-cipher"),
                    # Protocol Settings
                    "Min TLS Version":   (sps.findtext("min-version") or "-") if sps is not None else "-",
                    "Max TLS Version":   (sps.findtext("max-version") or "-") if sps is not None else "-",
                    "Allow SHA1":        _yn(sps,"auth-algo-sha1"),
                    "Allow 3DES":        _yn(sps,"enc-algo-3des"),
                    "Allow RC4":         _yn(sps,"enc-algo-rc4"),
                    # No Decrypt
                    "ND - Block Untrusted": _yn(nd,"block-untrusted-issuer"),
                    "ND - Block Expired":   _yn(nd,"block-expired-certificate"),
                    # SSH Proxy
                    "SSH - Block Unsupported": _yn(ssh,"block-unsupported-alg"),
                })
        return rows

    # ── SECURITY PROFILE GROUPS ────────────────────────────────────
    def get_security_profile_groups(self) -> list:
        pg = self.vsys.find("profile-group") if self.vsys is not None else None
        if pg is None:
            return []
        rows = []
        for e in pg.findall("entry"):
            row = {"Name": e.get("name","-")}
            for t in ["virus","spyware","vulnerability","url-filtering",
                      "file-blocking","data-filtering","wildfire-analysis"]:
                m = e.find(f"{t}/member")
                row[t.replace("-"," ").title()] = m.text if m is not None and m.text else "None"
            rows.append(row)
        return rows

    def get_security_profiles_summary(self) -> dict:
        profiles = self.vsys.find("profiles") if self.vsys is not None else None
        result = {}
        if profiles is None:
            return result
        for ptype in ["virus","spyware","vulnerability","url-filtering",
                      "wildfire-analysis","file-blocking"]:
            el = profiles.find(ptype)
            if el is not None:
                key = ptype.replace("-"," ").title()
                result[key] = [{"Profile Name": e.get("name","-"),
                                 "Description": e.findtext("description") or "-"}
                                for e in el.findall("entry")]
        return result

    # ── LOG FORWARDING ─────────────────────────────────────────────
    def get_log_forwarding_profiles(self) -> list:
        rows = []
        for src_el, loc in [
            (self.vsys.find("log-settings") if self.vsys else None, "vsys1"),
            (self._shared().find("log-settings") if self._shared() else None, "shared"),
        ]:
            if src_el is None:
                continue
            prof_el = src_el.find("profiles")
            if prof_el is None:
                continue
            for entry in prof_el.findall("entry"):
                pname = entry.get("name","-")
                desc  = entry.findtext("description") or "-"
                for ml in entry.findall("match-list/entry"):
                    rows.append({
                        "Name":           pname,
                        "Description":    desc,
                        "Log Type":       ml.findtext("log-type") or "-",
                        "Filter":         ml.findtext("filter") or "any",
                        "Panorama":       "Yes" if ml.find("send-panorama") is not None else "No",
                        "SNMP":           _members_el(ml.find("send-snmptrap"),"None"),
                        "Email":          _members_el(ml.find("send-email"),"None"),
                        "Syslog":         _members_el(ml.find("send-syslog"),"None"),
                        "HTTP":           _members_el(ml.find("send-http"),"None"),
                        "Quarantine":     ml.findtext("quarantine") or "-",
                        "Built-in Actions": ml.findtext("actions/entry/type") or "-",
                    })
        return rows

    # ── AUTHENTICATION ─────────────────────────────────────────────
    def get_auth_profiles(self) -> list:
        rows = []
        shared = self._shared()
        auth_el = shared.find("authentication-profile") if shared else None
        if auth_el is None:
            return []
        for entry in auth_el.findall("entry"):
            # Determine method
            type_el = entry.find("type")
            method = "-"
            if type_el is not None:
                for m in ["ldap","radius","kerberos","saml-idp","local-database","tacplus"]:
                    if type_el.find(m) is not None:
                        method = m.upper()
                        break
            allow_list = _members_el(entry.find("allow-list"))
            rows.append({
                "Name":       entry.get("name","-"),
                "Auth Method": method,
                "Allow List": allow_list,
                "Username Modifier": entry.findtext("username-modifier") or "-",
            })
        return rows

    def get_auth_sequences(self) -> list:
        shared = self._shared()
        seq_el = shared.find("authentication-sequence") if shared else None
        if seq_el is None:
            return []
        rows = []
        for entry in seq_el.findall("entry"):
            rows.append({
                "Name":     entry.get("name","-"),
                "Profiles": _members_el(entry.find("authentication-profiles")),
                "Use Next on Fail": entry.findtext("use-next-profile-on-fail") or "no",
            })
        return rows

    # ── SDWAN LINK MANAGEMENT ──────────────────────────────────────
    def get_sdwan_path_quality(self) -> list:
        # Try vsys profiles first (where we found it)
        pq_el = self.vsys.find("profiles/sdwan-path-quality") if self.vsys else None
        if pq_el is None:
            pq_el = (self.dev.find("network/sdwan/path-quality-profile")
                     if self.dev else None)
        if pq_el is None:
            return []
        rows = []
        for entry in pq_el.findall("entry"):
            metric = entry.find("metric")
            rows.append({
                "Name":        entry.get("name","-"),
                "Latency":     entry.findtext("latency") or
                               (metric.findtext("latency/threshold") if metric else "-") or "-",
                "Jitter":      entry.findtext("jitter") or
                               (metric.findtext("jitter/threshold") if metric else "-") or "-",
                "Packet Loss": entry.findtext("packet-loss") or
                               (metric.findtext("pkt-loss/threshold") if metric else "-") or "-",
            })
        return rows

    def get_sdwan_traffic_dist(self) -> list:
        # Try vsys profiles
        td_el = self.vsys.find("profiles/sdwan-traffic-distribution") if self.vsys else None
        if td_el is None:
            td_el = (self.dev.find("network/sdwan/traffic-distribution-profile")
                     if self.dev else None)
        if td_el is None:
            return []
        rows = []
        for entry in td_el.findall("entry"):
            link_tags = [e.get("name","") for e in entry.findall("link-tags/entry")]
            dist = (entry.findtext("traffic-distribution") or
                    entry.findtext("distribution-strategy") or "Best Available Path")
            rows.append({
                "Name":                 entry.get("name","-"),
                "Traffic Distribution": dist,
                "Link Tags":            ", ".join(link_tags) if link_tags else "-",
            })
        return rows

    def get_sdwan_saas_quality(self) -> list:
        el = (self.dev.find("network/sdwan/saas-quality-profile") if self.dev else None)
        if el is None:
            return []
        rows = []
        for entry in el.findall("entry"):
            rows.append({
                "Name":              entry.get("name","-"),
                "SaaS Monitor Mode": entry.findtext("path-quality-profile") or "-",
                "Monitored URL":     entry.findtext("saas-app") or "-",
                "Static IP":         entry.findtext("static-ip") or "-",
                "Probe Interval":    entry.findtext("probe-interval") or "-",
            })
        return rows

    def get_sdwan_error_correction(self) -> list:
        el = (self.dev.find("network/sdwan/error-correction-profile") if self.dev else None)
        if el is None:
            return []
        rows = []
        for entry in el.findall("entry"):
            fec  = entry.find("fec")
            pdup = entry.find("packet-duplication")
            rows.append({
                "Name":             entry.get("name","-"),
                "Activate Threshold": entry.findtext("activate-threshold") or "-",
                "EC Mode":          entry.findtext("mode") or "-",
                "FEC Enabled":      fec.findtext("enable","no") if fec else "no",
                "FEC Loss Ratio":   fec.findtext("loss-ratio","") if fec else "-",
                "FEC Recovery(ms)": fec.findtext("recovery-duration","") if fec else "-",
                "Dup Enabled":      pdup.findtext("enable","no") if pdup else "no",
                "Dup Recovery(ms)": pdup.findtext("recovery-duration","") if pdup else "-",
            })
        return rows

    # ── SCHEDULES ──────────────────────────────────────────────────
    def get_schedules(self) -> list:
        rows = []
        for src_el, loc in [
            (self.vsys.find("schedule") if self.vsys else None, "vsys1"),
            (self._shared().find("schedule") if self._shared() else None, "shared"),
        ]:
            if src_el is None:
                continue
            for entry in src_el.findall("entry"):
                st_el = entry.find("schedule-type")
                recurrence, times = "-", "-"
                if st_el is not None:
                    rec = st_el.find("recurring")
                    non = st_el.find("non-recurring")
                    if rec is not None:
                        daily  = rec.find("daily")
                        weekly = rec.find("weekly")
                        if daily is not None:
                            recurrence = "Daily"
                            times = ", ".join(m.text for m in daily.findall("member") if m.text)
                        elif weekly is not None:
                            recurrence = "Weekly"
                            day_times = []
                            for day in ["monday","tuesday","wednesday","thursday",
                                        "friday","saturday","sunday"]:
                                day_el = weekly.find(day)
                                if day_el is not None:
                                    t = ", ".join(m.text for m in day_el.findall("member") if m.text)
                                    day_times.append(f"{day.capitalize()}: {t}")
                            times = " | ".join(day_times) if day_times else "-"
                        else:
                            recurrence = "Recurring"
                    elif non is not None:
                        recurrence = "One-time"
                        times = ", ".join(m.text for m in non.findall("member") if m.text)
                rows.append({
                    "Name":       entry.get("name","-"),
                    "Location":   loc,
                    "Recurrence": recurrence,
                    "Times":      times,
                })
        return rows

    def get_application_groups(self) -> list:
        el = self.vsys.find("application-group") if self.vsys is not None else None
        if el is None:
            return []
        rows = []
        for entry in el.findall("entry"):
            rows.append({
                "Name":    entry.get("name","-"),
                "Members": _members_el(entry.find("members")),
            })
        return rows
