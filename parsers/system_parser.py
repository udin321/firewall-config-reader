import re


class SystemParserMixin:

    def parse_admins(self) -> list:
        block = self._extract_block("system admin")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(p, d="-"):
                m = re.search(p, body)
                return m.group(1).strip() if m else d
            trusted_hosts = []
            for i in range(1, 7):
                h = g(rf'set trusthost{i} ([\d\./]+)')
                if h != "-" and not h.startswith("0.0.0.0"):
                    trusted_hosts.append(h)
            rows.append({
                "Name":          name,
                "Profile":       g(r'set accprofile "([^"]+)"', "super_admin"),
                "Type":          "Local",
                "Trusted Hosts": ", ".join(trusted_hosts) if trusted_hosts else "Any",
                "2FA":           g(r'set two-factor (\S+)', "disable").capitalize(),
                "VDOM":          g(r'set vdom "([^"]+)"', "root"),
            })
        return rows

    def parse_accprofiles(self) -> list:
        block = self._extract_block("system accprofile")
        if not block:
            return []
        rows = []
        entries = re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', block, re.DOTALL | re.MULTILINE)
        for name, body in entries:
            def g(p, d="none"):
                m = re.search(p, body)
                return m.group(1).strip() if m else d
            def fmt(val):
                if val == "read-write": return "Read/Write"
                if val == "read":       return "Read"
                return "None"
            rows.append({
                "name":            name,
                "comments":        g(r'set comments "([^"]+)"', ""),
                "Security Fabric": fmt(g(r'set secfabgrp (\S+)')),
                "FortiView":       fmt(g(r'set ftviewgrp (\S+)')),
                "User & Device":   fmt(g(r'set authgrp (\S+)')),
                "Firewall":        fmt(g(r'set fwgrp (\S+)')),
                "Log & Report":    fmt(g(r'set loggrp (\S+)')),
                "Network":         fmt(g(r'set netgrp (\S+)')),
                "System":          fmt(g(r'set sysgrp (\S+)')),
                "Security Profile": fmt(g(r'set utmgrp (\S+)')),
                "VPN":             fmt(g(r'set vpngrp (\S+)')),
                "WiFi & Switch":   fmt(g(r'set wifi (\S+)')),
            })
        return rows

    def parse_system_settings(self) -> dict:
        block = self._extract_block("system global")
        if not block:
            return {}
        def g(p, d="-"):
            m = re.search(p, block)
            return m.group(1).strip() if m else d

        ntp_block = self._extract_block("system ntp")
        ntp = {}
        if ntp_block:
            status_m   = re.search(r'set status (\S+)', ntp_block)
            servers    = re.findall(r'set server "([^"]+)"', ntp_block)
            interval_m = re.search(r'set syncinterval (\d+)', ntp_block)
            ntp = {
                "status":   status_m.group(1) if status_m else "enable",
                "servers":  servers if servers else ["FortiGuard"],
                "interval": interval_m.group(1) if interval_m else "60",
            }

        # Password policy: only "enable" if explicitly set
        passwd_policy_m = re.search(r'set admin-password-policy (enable|disable)', block)
        passwd_policy   = passwd_policy_m.group(1) if passwd_policy_m else "disable"

        # Password scope
        passwd_scope_m = re.search(r'set password-policy-scope (\S+)', block)
        passwd_scope   = passwd_scope_m.group(1) if passwd_scope_m else "off"

        return {
            "hostname":       g(r'set hostname "?([^"\n]+)"?'),
            "timezone":       g(r'set timezone (\d+)'),
            "alias":          g(r'set alias "([^"]+)"'),
            "theme":          g(r'set gui-theme (\S+)', "default"),
            "http_port":      g(r'set admin-port (\d+)', "80"),
            "https_port":     g(r'set admin-sport (\d+)', "443"),
            "ssh_port":       g(r'set admin-ssh-port (\d+)', "22"),
            "telnet_port":    g(r'set admin-telnet-port (\d+)', "23"),
            "idle_timeout":   g(r'set admintimeout (\d+)', "5"),
            "http_redirect":  g(r'set admin-https-redirect (enable|disable)', "enable"),
            "forticloud_sso": g(r'set forticloud-account-enforcement (enable|disable)', "disable"),
            "passwd_policy":  passwd_policy,
            "passwd_scope":   passwd_scope,
            "workflow_mode":  g(r'set management-mode (\S+)', "automatic"),
            "ntp":            ntp,
            "switch_ctrl":    g(r'set switch-controller (enable|disable)', "disable"),
        }

    def parse_snmp(self) -> dict:
        sysinfo_block = self._extract_block("system snmp sysinfo")
        sysinfo = {}
        if sysinfo_block:
            def g(p, d="-"):
                m = re.search(p, sysinfo_block)
                return m.group(1).strip() if m else d
            sysinfo = {
                "status":      g(r'set status (enable|disable)', "disable"),
                "description": g(r'set description "([^"]+)"'),
                "location":    g(r'set location "([^"]+)"'),
                "contact":     g(r'set contact-info "([^"]+)"'),
            }
        communities = []
        comm_block = self._extract_block("system snmp community")
        if comm_block:
            for entry in re.findall(r'^\s*edit (\d+)(.*?)^\s*next', comm_block, re.DOTALL | re.MULTILINE):
                _, cbody = entry
                def g(p, d="-"):
                    m = re.search(p, cbody)
                    return m.group(1).strip() if m else d
                hosts = re.findall(r'set ip ([\d\./]+)', cbody)
                q1_m = re.search(r'set query-v1-status (enable|disable)', cbody)
                q2_m = re.search(r'set query-v2c-status (enable|disable)', cbody)
                t1_m = re.search(r'set trap-v1-status (enable|disable)', cbody)
                t2_m = re.search(r'set trap-v2c-status (enable|disable)', cbody)
                communities.append({
                    "Name":     g(r'set name "([^"]+)"'),
                    "Queries":  "Disable" if (q1_m and q1_m.group(1)=="disable") or (q2_m and q2_m.group(1)=="disable") else "Enable",
                    "Traps":    "Disable" if (t1_m and t1_m.group(1)=="disable") or (t2_m and t2_m.group(1)=="disable") else "Enable",
                    "Hosts":    ", ".join(hosts) if hosts else "Any",
                    "Status":   "Enable",
                })
        v3_users = []
        v3_block = self._extract_block("system snmp user")
        if v3_block:
            for entry in re.findall(r'^\s*edit "([^"]+)"(.*?)^\s*next', v3_block, re.DOTALL | re.MULTILINE):
                uname, ubody = entry
                def g(p, d="-"):
                    m = re.search(p, ubody)
                    return m.group(1).strip() if m else d
                notify_hosts = g(r'set notify-hosts ([\d\. ]+)')
                v3_users.append({
                    "Name":           uname,
                    "Security Level": g(r'set security-level (\S+)', "auth-priv").replace("-", " ").title(),
                    "Queries":        "Enable",
                    "Traps":          "Enable" if notify_hosts != "-" else "Disable",
                    "Hosts":          notify_hosts.strip() if notify_hosts != "-" else "Any",
                    "Auth Protocol":  g(r'set auth-proto (\S+)', "sha").upper(),
                    "Priv Protocol":  g(r'set priv-proto (\S+)', "aes256").upper(),
                    "Status":         "Enable",
                })
        return {
            "sysinfo":     sysinfo,
            "communities": communities,
            "v3_users":    v3_users,
        }

    def parse_ha_config(self) -> dict:
        block = self._extract_block("system ha")
        if not block:
            return {"mode": "standalone"}
        def g(p, d="-"):
            m = re.search(p, block)
            return m.group(1).strip() if m else d
        mode = g(r'set mode (\S+)', "standalone")
        if mode == "standalone":
            return {"mode": "standalone"}
        monitor_m = re.search(r'set monitor (.*)', block)
        monitor_intfs = re.findall(r'"([^"]+)"', monitor_m.group(1)) if monitor_m else []
        hbdev_m = re.search(r'set hbdev (.*)', block)
        hbdev   = hbdev_m.group(1).strip() if hbdev_m else "-"
        mgmt_block    = self._extract_sub_block(block, "management-interface")
        mgmt_reserved = []
        if mgmt_block:
            for entry in re.findall(r'^\s*edit (\d+)(.*?)^\s*next', mgmt_block, re.DOTALL | re.MULTILINE):
                _, mbody = entry
                def g2(p, d="-"):
                    m = re.search(p, mbody)
                    return m.group(1).strip() if m else d
                mgmt_reserved.append({
                    "Interface":   g2(r'set interface "([^"]+)"'),
                    "Gateway":     g2(r'set gateway ([\d\.]+)'),
                    "Destination": g2(r'set dst ([\d\./]+)'),
                })
        return {
            "mode":           "a-p" if mode == "a-p" else "a-a",
            "group_id":       g(r'set group-id (\d+)'),
            "group_name":     g(r'set group-name "([^"]+)"'),
            "priority":       g(r'set priority (\d+)'),
            "session_pickup": g(r'set session-pickup (enable|disable)', "disable"),
            "override":       g(r'set override (enable|disable)', "disable"),
            "hbdev":          hbdev,
            "monitor":        monitor_intfs,
            "mgmt_reserved":  mgmt_reserved,
        }

    def parse_log_settings(self) -> dict:
        """Fixed: properly read resolve-ip and resolve-app from log setting."""
        block    = self._extract_block("log setting")
        mem_block    = self._extract_block("log memory setting")
        syslog_block = self._extract_block("log syslogd setting")

        def g(b, p, d="disable"):
            if not b:
                return d
            m = re.search(p, b)
            return m.group(1).strip() if m else d

        return {
            "fwpolicy_implicit": g(block, r'set fwpolicy-implicit-log (enable|disable)'),
            "local_in_allow":    g(block, r'set local-in-allow (enable|disable)'),
            "local_in_deny_uni": g(block, r'set local-in-deny-unicast (enable|disable)'),
            "local_in_deny_brd": g(block, r'set local-in-deny-broadcast (enable|disable)'),
            # These are in log setting block — correct key names
            "resolve_hosts":     g(block, r'set resolve-ip (enable|disable)'),
            "resolve_apps":      g(block, r'set resolve-app (enable|disable)'),
            "memory_log":        g(mem_block, r'set status (enable|disable)'),
            "syslog_enabled":    g(syslog_block, r'set status (enable|disable)'),
        }

    def parse_threat_weight(self) -> dict:
        block = self._extract_block("log threat-weight")
        if not block:
            return {}
        THREAT_LEVELS = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}
        FTGD_NAMES = {
            "26": "Nudity", "61": "Lingerie/Swimsuit", "86": "Adult Materials",
            "1":  "Drug Abuse", "3": "Weapons", "4": "Violence", "5": "Racism/Hate",
            "6":  "Phishing/Fraud", "12": "Proxy Avoidance", "59": "Charitable Organizations",
            "62": "Marijuana", "83": "Anonymizers", "72": "Real Estate",
            "14": "Spyware/Malware", "96": "Terrorism",
        }
        APP_CAT_NAMES = {"2": "P2P", "6": "Proxy"}

        def _extract_sub(b, keyword):
            marker = f"config {keyword}"
            start = b.find(marker)
            if start == -1:
                return ""
            depth = 0
            lines = b[start:].splitlines()
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

        web_weights = {}
        web_sub = _extract_sub(block, "web")
        if web_sub:
            for entry in re.findall(r'^\s*edit \d+(.*?)^\s*next', web_sub, re.DOTALL | re.MULTILINE):
                cat_m   = re.search(r'set category (\d+)', entry)
                level_m = re.search(r'set level (\S+)', entry)
                if cat_m:
                    cat_id = cat_m.group(1)
                    web_weights[FTGD_NAMES.get(cat_id, f"Cat {cat_id}")] = THREAT_LEVELS.get(level_m.group(1), "Low") if level_m else "Low"

        app_weights = {}
        app_sub = _extract_sub(block, "application")
        if app_sub:
            for entry in re.findall(r'^\s*edit \d+(.*?)^\s*next', app_sub, re.DOTALL | re.MULTILINE):
                cat_m   = re.search(r'set category (\d+)', entry)
                level_m = re.search(r'set level (\S+)', entry)
                if cat_m:
                    cat_id = cat_m.group(1)
                    app_weights[APP_CAT_NAMES.get(cat_id, f"AppCat {cat_id}")] = THREAT_LEVELS.get(level_m.group(1), "Low") if level_m else "Low"

        def g(p, d="medium"):
            m = re.search(p, block)
            return THREAT_LEVELS.get(m.group(1), "Medium") if m else THREAT_LEVELS.get(d, "Medium")

        return {
            "status":         re.search(r'set status (enable|disable)', block).group(1) if re.search(r'set status (enable|disable)', block) else "enable",
            "blocked_conn":   g(r'set blocked-connection (\S+)'),
            "failed_conn":    g(r'set failed-connection (\S+)'),
            "url_block":      g(r'set url-block-detected (\S+)'),
            "malware":        g(r'set malware (\S+)'),
            "ips_detect":     g(r'set ips-detect (\S+)'),
            "botnet":         g(r'set botnet-connection (\S+)'),
            "web_weights":    web_weights,
            "app_weights":    app_weights,
        }
