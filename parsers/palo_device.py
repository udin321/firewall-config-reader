"""Palo Alto Device parser – full rebuild."""
from parsers.paloalto import PaloAltoParser, _members_el


def _tick(val):
    return "✓" if str(val).lower() in ["yes","true","enable","1"] else ""


class PaloDeviceParser(PaloAltoParser):

    def _dc(self):
        return self.dev.find("deviceconfig") if self.dev else None

    def _sys(self):
        dc = self._dc()
        return dc.find("system") if dc else None

    def _setting(self):
        dc = self._dc()
        return dc.find("setting") if dc else None

    def _shared(self):
        return self.root.find("shared") if self.root else None

    def _mgt_config(self):
        return self.root.find("mgt-config") if self.root else None

    # ── SETUP / MANAGEMENT ──────────────────────────────────────
    def get_general_settings(self) -> dict:
        s = self._sys()
        if s is None:
            return {}
        return {
            "Hostname":              s.findtext("hostname", "-"),
            "Domain":                s.findtext("domain", "-"),
            "Timezone":              s.findtext("timezone", "-"),
            "Login Banner":          s.findtext("login-banner", "-"),
            "SSL/TLS Service Profile": s.findtext("ssl-tls-service-profile", "-"),
            "Multi Virtual System":  s.findtext("multi-vsys", "no"),
            "Advanced Routing":      s.findtext("advanced-routing-engine", "no"),
            "Cert Expiry Check":     s.findtext("certificate-expiry-check", "no"),
            "Tunnel Acceleration":   s.findtext("tunnel-acceleration", "no"),
        }

    def get_panorama_settings(self) -> dict:
        s = self._sys()
        if s is None:
            return {}
        return {
            "Panorama Server":       s.findtext("panorama-server", "-"),
            "Panorama Server 2":     s.findtext("panorama-server-2", "-"),
            "Receive Timeout (sec)": s.findtext("panorama-receive-timeout", "-"),
            "Send Timeout (sec)":    s.findtext("panorama-send-timeout", "-"),
        }

    def get_auth_settings(self) -> dict:
        s = self._sys()
        if s is None:
            return {}
        return {
            "Auth Profile":          s.findtext("authentication-profile", "-"),
            "Idle Timeout (min)":    s.findtext("idle-timeout", "-"),
            "Failed Attempts":       s.findtext("failed-attempts", "-"),
            "Lockout Time (min)":    s.findtext("lockout-time", "-"),
            "Max Session Count":     s.findtext("max-session-count", "-"),
            "Max Session Time (min)": s.findtext("max-session-time", "-"),
        }

    def get_logging_settings(self) -> dict:
        s = self._sys()
        mg = self._setting().find("management") if self._setting() else None
        if s is None:
            return {}
        return {
            "Config Audit Versions":    s.findtext("config-audit-count", "-"),
            "Max CSV Rows":             s.findtext("max-rows-in-csv-export", "-"),
            "Max User Activity Rows":   s.findtext("max-rows-in-user-activity-report", "-"),
            "Send Hostname in Syslog":  _tick(s.findtext("syslog-hostname", "no")),
            "Report Runtime":           s.findtext("report-run-time", "-"),
            "Report Expiration (days)": s.findtext("report-expiration-period", "-"),
            "Stop Traffic LogDB Full":  _tick(s.findtext("stop-traffic-logdb-full", "no")),
            "Enable Threat Vault":      _tick(s.findtext("threat-vault-access", "no")),
            "Log Admin Activity":       _tick(s.findtext("admin-activity-logging", "no")),
        }

    def get_password_complexity(self) -> dict:
        s = self._sys()
        if s is None:
            return {}
        pc = s.find("password-complexity")
        if pc is None:
            return {"Enabled": "no"}
        return {
            "Enabled":                _tick(pc.findtext("enabled", "no")),
            "Min Length":             pc.findtext("minimum-length", "-"),
            "Min Uppercase":          pc.findtext("minimum-uppercase-letters", "-"),
            "Min Lowercase":          pc.findtext("minimum-lowercase-letters", "-"),
            "Min Numeric":            pc.findtext("minimum-numeric-letters", "-"),
            "Min Special":            pc.findtext("minimum-special-characters", "-"),
            "Block Repeated":         _tick(pc.findtext("block-repeated-characters", "no")),
            "Block Username":         _tick(pc.findtext("block-username-inclusion", "no")),
            "Password Differ By":     pc.findtext("new-password-differs-by-characters", "-"),
            "Change on First Login":  _tick(pc.findtext("password-change-on-install", "no")),
            "Reuse Limit":            pc.findtext("password-history-count", "-"),
            "Block Change Period (days)": pc.findtext("password-change-period", "-"),
            "Required Change (days)": pc.findtext("expiration-period", "-"),
            "Expiry Warning (days)":  pc.findtext("password-change-announcement-period", "-"),
        }

    def get_services_config(self) -> dict:
        s = self._sys()
        if s is None:
            return {}
        dns = s.find("dns-setting/servers")
        ntp = s.find("ntp-servers")
        return {
            "Primary DNS":    dns.findtext("primary", "-") if dns is not None else "-",
            "Secondary DNS":  dns.findtext("secondary", "-") if dns is not None else "-",
            "Primary NTP":    ntp.findtext("primary-ntp-server/ntp-server-address", "-") if ntp else "-",
            "Primary NTP Auth": ntp.findtext("primary-ntp-server/authentication-type", "-") if ntp else "-",
            "Secondary NTP":  ntp.findtext("secondary-ntp-server/ntp-server-address", "-") if ntp else "-",
            "Timezone":       s.findtext("timezone", "-"),
        }

    def get_service_routes(self) -> list:
        dc = self._dc()
        sr = dc.find("service-route/v4") if dc else None
        if sr is None:
            return []
        rows = []
        for entry in sr.findall("entry"):
            rows.append({
                "Service":        entry.get("name", "-"),
                "Source Interface": entry.findtext("source", "-"),
                "Source Address": entry.findtext("source-address", "-"),
            })
        return rows

    def get_mgmt_services(self) -> dict:
        """Return which management services are enabled/disabled."""
        s = self._sys()
        svc = s.find("service") if s is not None else None
        def _s(tag):
            return (svc.findtext(tag) or "no") if svc is not None else "no"
        return {
            "disable_telnet": _s("disable-telnet"),
            "disable_http":   _s("disable-http"),
            "disable_https":  _s("disable-https"),
            "disable_ssh":    _s("disable-ssh"),
        }

    def get_mgmt_interface(self) -> dict:
        s = self._sys()
        if s is None:
            return {}
        return {
            "IP Address":      s.findtext("ip-address", "-"),
            "Netmask":         s.findtext("netmask", "-"),
            "Default Gateway": s.findtext("route/entry/nexthop/ip-address", "-") if s.find("route") else "-",
            "Speed":           s.findtext("speed-duplex", "-"),
        }

    # ── HIGH AVAILABILITY ────────────────────────────────────────
    def get_ha_general(self) -> dict:
        dc = self._dc()
        ha = dc.find("high-availability") if dc else None
        if ha is None:
            return {"enabled": "no"}

        # PAN-OS: <enabled>yes</enabled> under <high-availability>
        enabled_raw = ha.findtext("enabled", "no")
        if enabled_raw.lower() not in ("yes", "true", "1"):
            return {"enabled": "no"}

        grp  = ha.find("group")
        mode = "active-passive"
        if grp is not None:
            mode_el = grp.find("mode")
            if mode_el is not None and mode_el.find("active-active") is not None:
                mode = "active-active"

        # device-priority: explicit value, else PAN-OS default is 100
        priority_raw = grp.findtext("election-option/device-priority", "") if grp else ""
        priority = priority_raw if priority_raw else "100"

        # Active/Passive extra settings
        ap = grp.find("active-passive") if grp else None
        passive_link_state          = ap.findtext("passive-link-state", "shutdown") if ap else "shutdown"
        monitor_fail_hold_down_time = ap.findtext("monitor-fail-hold-down-time", "1") if ap else "1"

        return {
            "enabled":                      "yes",
            "group_id":                     grp.findtext("group-id", "-") if grp else "-",
            "description":                  grp.findtext("description", "") if grp else "",
            "mode":                         mode,
            "config_sync":                  grp.findtext("configuration-synchronization/enabled", "no") if grp else "no",
            "peer_ha1_ip":                  grp.findtext("peer-ip", "-") if grp else "-",
            "backup_peer":                  grp.findtext("peer-ip-backup", "-") if grp else "-",
            "priority":                     priority,
            "preemptive":                   grp.findtext("election-option/preemptive", "no") if grp else "no",
            "passive_link_state":           passive_link_state,
            "monitor_fail_hold_down_time":  monitor_fail_hold_down_time,
        }

    def get_ha_interfaces(self) -> dict:
        dc = self._dc()
        ha = dc.find("high-availability") if dc else None
        if ha is None:
            return {}
        intf = ha.find("interface")
        if intf is None:
            return {}

        def _p(tag):
            el = intf.find(tag)
            if el is None:
                return {}
            return {
                "port":     el.findtext("port", "-"),
                "ip":       el.findtext("ip-address", "-"),
                "netmask":  el.findtext("netmask", "-"),
                "gateway":  el.findtext("gateway", ""),
                "encrypt":  _tick(el.findtext("encryption/enabled", "no")),
                "mon_hold": el.findtext("monitor-hold-time", "-"),
            }

        ha2 = _p("ha2")
        grp = ha.find("group")
        if grp is not None:
            ss = grp.find("state-synchronization")
            if ss is not None:
                ha2["transport"]  = ss.findtext("transport", "-")
                ka = ss.find("ha2-keep-alive")
                if ka is not None:
                    ha2["keepalive"] = _tick(ka.findtext("enabled", "no"))
                    ha2["ka_action"] = ka.findtext("action", "-")
        return {"ha1": _p("ha1"), "ha1_backup": _p("ha1-backup"),
                "ha2": ha2,       "ha2_backup": _p("ha2-backup")}

    def get_ha_link_path_monitoring(self) -> dict:
        dc = self._dc()
        ha = dc.find("high-availability") if dc else None
        grp = ha.find("group") if ha else None
        if grp is None:
            # PAN-OS enables link & path monitoring by default even when
            # the config block is absent — show as enabled, not disabled.
            return {
                "link_enabled":   "yes",
                "link_fail_cond": "any",
                "link_groups":    [],
                "path_enabled":   "yes",
                "path_fail_cond": "any",
                "path_groups":    [],
                "_defaults_note": "Link & Path Monitoring enabled by PAN-OS default (no explicit config found)",
            }

        lm = grp.find("link-monitoring")
        link_groups = []
        if lm is not None:
            for e in lm.findall("link-group/entry"):
                intfs = [m.text for m in e.findall("interface/member") if m.text]
                link_groups.append({
                    "Name":      e.get("name", "-"),
                    "Enabled":   _tick(e.findtext("enabled", "yes")),
                    "Fail Cond": e.findtext("failure-condition", "any"),
                    "Interfaces": ", ".join(intfs),
                })
        # PAN-OS default for link-monitoring/enable is "yes"
        link_enabled = lm.findtext("enable", "yes") if lm is not None else "yes"

        pm = grp.find("path-monitoring")
        path_groups = []
        if pm is not None:
            for e in pm.findall("path-group/entry"):
                dests = [x.get("name", "") for x in e.findall("destination-ip/entry")]
                path_groups.append({
                    "Name":      e.get("name", "-"),
                    "Enabled":   _tick(e.findtext("enabled", "yes")),
                    "Fail Cond": e.findtext("failure-condition", "any"),
                    "Source IP": e.findtext("source-ip", "-"),
                    "Dest IPs":  ", ".join(dests),
                    "Interval":  e.findtext("interval", "200"),
                    "Count":     e.findtext("count", "10"),
                })
        # PAN-OS default for path-monitoring/enable is "yes"
        path_enabled = pm.findtext("enable", "yes") if pm is not None else "yes"

        return {
            "link_enabled":    link_enabled,
            "link_fail_cond":  lm.findtext("failure-condition", "any") if lm is not None else "any",
            "link_groups":     link_groups,
            "path_enabled":    path_enabled,
            "path_fail_cond":  pm.findtext("failure-condition", "any") if pm is not None else "any",
            "path_groups":     path_groups,
        }

    # ── ADMINISTRATORS ───────────────────────────────────────────
    def get_admins(self) -> list:
        mgt = self._mgt_config()
        users_el = mgt.find("users") if mgt else None
        if users_el is None:
            return []
        rows = []
        for entry in users_el.findall("entry"):
            role = "custom"
            perm = entry.find("permissions/role-based")
            if perm is not None:
                if perm.find("superuser") is not None:       role = "superuser"
                elif perm.find("superreader") is not None:   role = "superuser (read-only)"
                elif perm.find("deviceadmin") is not None:   role = "device admin"
                elif perm.find("devicereader") is not None:  role = "device admin (read-only)"
            rows.append({
                "Name":          entry.get("name", "-"),
                "Role":          role,
                "Auth Profile":  entry.findtext("authentication-profile", "-"),
                "Description":   entry.findtext("description", "-"),
                "Password Profile": entry.findtext("password-profile", "-"),
            })
        return rows

    # ── PASSWORD PROFILES ────────────────────────────────────────
    def get_password_profiles(self) -> list:
        mgt = self._mgt_config()
        pp  = mgt.find("password-complexity") if mgt else None
        if pp is None:
            return []
        rows = []
        for entry in pp.findall("entry"):
            rows.append({
                "Name":              entry.get("name", "-"),
                "Change Period":     entry.findtext("password-change-period", "-"),
                "Expiry Warning":    entry.findtext("password-change-announcement-period", "-"),
                "Min Length":        entry.findtext("minimum-length", "-"),
                "Min Uppercase":     entry.findtext("minimum-uppercase-letters", "-"),
                "Min Lowercase":     entry.findtext("minimum-lowercase-letters", "-"),
                "Min Numeric":       entry.findtext("minimum-numeric-letters", "-"),
                "Min Special":       entry.findtext("minimum-special-characters", "-"),
                "History Count":     entry.findtext("password-history-count", "-"),
                "Block Username":    _tick(entry.findtext("block-username-as-password", "no")),
                "Block Repeated":    _tick(entry.findtext("block-repeated-characters", "no")),
                "Failed Attempts":   entry.findtext("lockout/failed-attempts", "-"),
                "Lockout Time (min)": entry.findtext("lockout/lockout-period", "-"),
            })
        return rows

    # ── ADMIN ROLES ──────────────────────────────────────────────
    def get_admin_roles(self) -> list:
        mc = self._mgt_config()
        rows = []
        if mc:
            for entry in mc.findall(".//custom/entry"):
                rows.append({
                    "Name":        entry.get("name", "-"),
                    "Role":        "Custom",
                    "CLI Role":    entry.findtext("cli-role", "-"),
                    "Description": entry.findtext("description", "-"),
                })
        return rows

    # ── AUTHENTICATION PROFILES ──────────────────────────────────
    def get_auth_profiles(self) -> list:
        shared = self._shared()
        auth_el = shared.find("authentication-profile") if shared else None
        if auth_el is None:
            return []
        rows = []
        for entry in auth_el.findall("entry"):
            method = "-"
            server_profile = "-"
            mt = entry.find("method")
            if mt is not None:
                for child in mt:
                    method = child.tag
                    sp = child.find("server-profile")
                    if sp is not None and sp.text:
                        server_profile = sp.text
                    break
            rows.append({
                "Name":           entry.get("name", "-"),
                "Method":         method,
                "Server Profile": server_profile,
                "Allow List":     _members_el(entry.find("allow-list")),
                "MFA":            _tick(entry.findtext("multi-factor-auth/mfa-enable", "no")),
                "Failed Attempts": entry.findtext("lockout/failed-attempts", "-"),
                "Lockout Time":   entry.findtext("lockout/lockout-time", "-"),
                "User Domain":    entry.findtext("user-domain", "-"),
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
                "Name":       entry.get("name", "-"),
                "Location":   "shared",
                "Profiles":   _members_el(entry.find("authentication-profiles")),
                "Use Next":   _tick(entry.findtext("use-next-profile-on-fail", "no")),
            })
        return rows

    # ── USER ID ──────────────────────────────────────────────────
    def get_user_id_info(self) -> dict:
        setting = self._setting()
        uid = setting.find("user-id") if setting else None
        if uid is None:
            return {}

        server_monitoring = []
        for sm in uid.findall("server-monitor/entry"):
            server_monitoring.append({
                "Name":    sm.get("name", "-"),
                "Enabled": _tick(sm.findtext("enabled", "yes")),
                "Type":    sm.findtext("type", "-"),
                "Address": sm.findtext("network-address", "-"),
            })

        inc_exc = []
        for net in uid.findall("include-list/entry"):
            inc_exc.append({"Type": "Include", "Network": net.get("name", "-")})
        for net in uid.findall("exclude-list/entry"):
            inc_exc.append({"Type": "Exclude", "Network": net.get("name", "-")})

        ts_agents = []
        for tsa in uid.findall("terminal-server-agent/entry"):
            ts_agents.append({
                "Name":    tsa.get("name", "-"),
                "Enabled": _tick(tsa.findtext("enabled", "yes")),
                "Host":    tsa.findtext("host-or-ip", "-"),
                "Port":    tsa.findtext("port", "5009"),
            })

        group_mappings = []
        for gm in uid.findall("group-mapping/entry"):
            group_mappings.append({
                "Name":            gm.get("name", "-"),
                "Enabled":         _tick(gm.findtext("enabled", "yes")),
                "Server Profile":  gm.findtext("server-profile", "-"),
                "Update Interval": gm.findtext("update-interval", "-"),
            })

        trusted_src = [m.text for m in uid.findall("xml-api/trusted-source-address/member") if m.text]

        ap = uid.find("authentication-portal")
        auth_portal = {}
        if ap is not None:
            auth_portal = {
                "Enabled":       _tick(ap.findtext("enabled", "yes")),
                "Idle Timer":    ap.findtext("idle-timer", "-"),
                "Mode":          ap.findtext("mode", "-"),
                "Auth Profile":  ap.findtext("authentication-profile", "-"),
                "SSL Profile":   ap.findtext("ssl-tls-service-profile", "-"),
            }

        return {
            "server_monitoring": server_monitoring,
            "inc_exc":           inc_exc,
            "ts_agents":         ts_agents,
            "group_mappings":    group_mappings,
            "trusted_src":       trusted_src,
            "auth_portal":       auth_portal,
            "uid_cert_profile":  uid.findtext("agent-collector-setting/agent-certificate", "-"),
        }

    # ── CERTIFICATES ─────────────────────────────────────────────
    def get_certificates(self) -> list:
        shared = self._shared()
        cert_el = shared.find("certificate") if shared else None
        if cert_el is None:
            return []
        from datetime import datetime
        rows = []
        for entry in cert_el.findall("entry"):
            exp = entry.findtext("not-valid-after", "-")
            status = "-"
            try:
                exp_dt = datetime.strptime(exp, "%b %d %H:%M:%S %Y GMT")
                diff   = (exp_dt - datetime.utcnow()).days
                status = "Expired" if diff < 0 else ("Expiring Soon" if diff < 30 else "Valid")
            except Exception:
                pass
            rows.append({
                "Name":       entry.get("name", "-"),
                "Common Name": entry.findtext("common-name", "-"),
                "Subject":    entry.findtext("subject", "-"),
                "Issuer":     entry.findtext("issuer", "-"),
                "CA":         _tick(entry.findtext("ca", "no")),
                "Key":        "✓" if entry.find("private-key") is not None else "",
                "Algorithm":  entry.findtext("algorithm", "-"),
                "Not Before": entry.findtext("not-valid-before", "-"),
                "Expires":    exp,
                "Status":     status,
            })
        return rows

    def get_ssl_tls_profiles(self) -> list:
        shared = self._shared()
        prof_el = shared.find("ssl-tls-service-profile") if shared else None
        if prof_el is None:
            return []
        rows = []
        for entry in prof_el.findall("entry"):
            ps = entry.find("protocol-settings")
            def _yes(prefix):
                if ps is None: return "-"
                items = [c.tag.replace(f"{prefix}-","") for c in ps
                         if c.tag.startswith(prefix) and c.text == "yes"]
                return ", ".join(items) if items else "-"
            rows.append({
                "Name":         entry.get("name", "-"),
                "Certificate":  entry.findtext("certificate", "-"),
                "Min TLS":      ps.findtext("min-version", "-") if ps else "-",
                "Max TLS":      ps.findtext("max-version", "-") if ps else "-",
                "Key Exchange": _yes("keyxchg-algo"),
                "Encryption":   _yes("enc-algo"),
                "Auth":         _yes("auth-algo"),
            })
        return rows

    def get_certificate_profiles(self) -> list:
        shared = self._shared()
        cp_el = shared.find("certificate-profile") if shared else None
        if cp_el is None:
            return []
        rows = []
        for entry in cp_el.findall("entry"):
            cas = [ca.get("name", "-") for ca in entry.findall("CA/entry")]
            rows.append({
                "Name":           entry.get("name", "-"),
                "Username Field": entry.findtext("username-field", "-"),
                "User Domain":    entry.findtext("domain", "-"),
                "CA Certs":       ", ".join(cas) if cas else "-",
                "Use CRL":        _tick(entry.findtext("use-crl", "no")),
                "Use OCSP":       _tick(entry.findtext("use-ocsp", "no")),
                "Block Unknown":  _tick(entry.findtext("block-unknown-cert", "no")),
                "Block Timeout":  _tick(entry.findtext("block-timeout-cert", "no")),
                "Block Expired":  _tick(entry.findtext("block-sessions-with-expired-cert", "no")),
            })
        return rows

    # ── LOCAL USER DATABASE ──────────────────────────────────────
    def get_local_users(self) -> list:
        shared = self._shared()
        ludb = shared.find("local-user-database") if shared else None
        if ludb is None: return []
        users_el = ludb.find("user")
        if users_el is None: return []
        rows = []
        for entry in users_el.findall("entry"):
            disabled = entry.findtext("disabled", "no")
            rows.append({
                "Name":    entry.get("name", "-"),
                "Enabled": _tick("no" if disabled == "yes" else "yes"),
            })
        return rows

    def get_local_user_groups(self) -> list:
        shared = self._shared()
        ludb = shared.find("local-user-database") if shared else None
        if ludb is None: return []
        grps_el = ludb.find("user-group")
        if grps_el is None: return []
        rows = []
        for entry in grps_el.findall("entry"):
            members = [m.text for m in entry.findall("user/member") if m.text]
            rows.append({
                "Name":    entry.get("name", "-"),
                "Count":   len(members),
                "Members": ", ".join(members[:15]) + ("..." if len(members) > 15 else ""),
            })
        return rows

    # ── LOG SETTINGS ─────────────────────────────────────────────
    def get_log_settings_tables(self) -> dict:
        result = {}
        ls_dev    = self.dev.find("log-settings") if self.dev else None
        ls_shared = self._shared().find("log-settings") if self._shared() else None
        for log_type in ["system","configuration","user-id","hip-match","globalprotect","iptag"]:
            rows = []
            for ls in [ls_dev, ls_shared]:
                if ls is None: continue
                lt_el = ls.find(log_type)
                if lt_el is None: continue
                for entry in lt_el.findall("match-list/entry"):
                    rows.append({
                        "Name":        entry.get("name","-"),
                        "Description": entry.findtext("description","-"),
                        "Filter":      entry.findtext("filter","any"),
                        "Panorama":    _tick(entry.findtext("send-panorama","no")),
                        "SNMP":        _members_el(entry.find("send-snmptrap"),""),
                        "Email":       _members_el(entry.find("send-email"),""),
                        "Syslog":      _members_el(entry.find("send-syslog"),""),
                        "HTTP":        _members_el(entry.find("send-http"),""),
                        "Built-in":    entry.findtext("actions/entry/type","-"),
                    })
            result[log_type] = rows
        return result

    def get_alarm_settings(self) -> dict:
        setting = self._setting()
        alarm = setting.find("management/alarm") if setting else None
        if alarm is None:
            return {}
        st = alarm.find("storage-thresholds")
        sv = alarm.find("security-violations")
        vl = alarm.find("violations")
        return {
            "Enable Alarms":           _tick(alarm.findtext("enable-alarm","no")),
            "CLI Notifications":       _tick(alarm.findtext("enable-cli-logging","no")),
            "Web Notifications":       _tick(alarm.findtext("enable-web-logging","no")),
            "Audible Alarms":          _tick(alarm.findtext("enable-audible-alarm","no")),
            "Enc/Dec Threshold":       alarm.findtext("enc-dec-threshold","-"),
            "Traffic Log DB":          st.findtext("traffic-log","-") if st else "-",
            "Threat Log DB":           st.findtext("threat-log","-") if st else "-",
            "Config Log DB":           st.findtext("config-log","-") if st else "-",
            "System Log DB":           st.findtext("system-log","-") if st else "-",
            "Sec Violations Threshold": sv.findtext("threshold","-") if sv else "-",
            "Sec Violations Period":   sv.findtext("time-period","-") if sv else "-",
            "Violations Threshold":    vl.findtext("threshold","-") if vl else "-",
            "Violations Period":       vl.findtext("time-period","-") if vl else "-",
            "Security Policy Tags":    _members_el(alarm.find("security-policy-tags"),""),
        }

    # ── SERVER PROFILES ──────────────────────────────────────────
    def _sp(self, tag):
        shared = self._shared()
        el = shared.find(f"server-profile/{tag}") if shared else None
        return el

    def get_radius_profiles(self) -> list:
        el = self._sp("radius")
        if el is None: return []
        rows = []
        for entry in el.findall("entry"):
            proto_el = entry.find("protocol")
            proto = "PAP"
            if proto_el:
                for p in ["CHAP","PAP","PEAP-MSCHAPv2"]:
                    if proto_el.find(p) is not None or proto_el.find(p.lower()) is not None:
                        proto = p; break
            servers = [f"{s.get('name','-')}: {s.findtext('ip-address','-')}:{s.findtext('port','1812')}"
                       for s in entry.findall("server/entry")]
            rows.append({"Name": entry.get("name","-"), "Protocol": proto,
                         "Servers": " | ".join(servers), "Timeout": entry.findtext("timeout","-")})
        return rows

    def get_ldap_profiles(self) -> list:
        el = self._sp("ldap")
        if el is None: return []
        rows = []
        for entry in el.findall("entry"):
            servers = [f"{s.get('name','-')}: {s.findtext('address','-')}:{s.findtext('port','389')}"
                       for s in entry.findall("server/entry")]
            rows.append({
                "Name":     entry.get("name","-"),
                "Type":     entry.findtext("ldap-type","-"),
                "Servers":  " | ".join(servers),
                "Base DN":  entry.findtext("base","-"),
                "Bind DN":  entry.findtext("bind-dn","-"),
                "SSL":      _tick(entry.findtext("ssl","no")),
                "Verify":   _tick(entry.findtext("verify-server-certificate","no")),
            })
        return rows

    def get_syslog_profiles(self) -> list:
        el = self._sp("syslog")
        if el is None: return []
        rows = []
        for entry in el.findall("entry"):
            for s in entry.findall("server/entry"):
                rows.append({
                    "Profile":   entry.get("name","-"),
                    "Server":    s.get("name","-"),
                    "Address":   s.findtext("server","-"),
                    "Transport": s.findtext("transport","UDP"),
                    "Port":      s.findtext("port","514"),
                    "Format":    s.findtext("format","BSD"),
                    "Facility":  s.findtext("facility","-"),
                })
        return rows

    def get_email_profiles(self) -> list:
        el = self._sp("email")
        if el is None: return []
        rows = []
        for entry in el.findall("entry"):
            for s in entry.findall("server/entry"):
                rows.append({
                    "Profile": entry.get("name","-"),
                    "Server":  s.get("name","-"),
                    "From":    s.findtext("from","-"),
                    "To":      s.findtext("to","-"),
                    "Gateway": s.findtext("gateway","-"),
                    "Port":    s.findtext("port","25"),
                    "Protocol": s.findtext("protocol","SMTP"),
                })
        return rows

    def get_snmp_profiles(self) -> list:
        el = self._sp("snmptrap")
        if el is None: return []
        rows = []
        for entry in el.findall("entry"):
            rows.append({"Name": entry.get("name","-"), "Version": entry.findtext("version","-")})
        return rows

    def get_http_profiles(self) -> list:
        el = self._sp("http")
        if el is None: return []
        rows = []
        for entry in el.findall("entry"):
            for s in entry.findall("server/entry"):
                rows.append({
                    "Profile":  entry.get("name","-"),
                    "Server":   s.get("name","-"),
                    "Address":  s.findtext("address","-"),
                    "Protocol": s.findtext("protocol","HTTPS"),
                    "Port":     s.findtext("port","443"),
                    "Method":   s.findtext("http-method","POST"),
                })
        return rows

    # ── DNS / NTP ────────────────────────────────────────────────
    def get_ntp(self) -> dict:
        s = self._sys()
        ntp = s.find("ntp-servers") if s else None
        if ntp is None: return {"primary": "-", "secondary": "-"}
        return {
            "primary":   ntp.findtext("primary-ntp-server/ntp-server-address","-"),
            "secondary": ntp.findtext("secondary-ntp-server/ntp-server-address","-"),
        }

    def get_dns(self) -> dict:
        s = self._sys()
        dns = s.find("dns-setting/servers") if s else None
        if dns is None: return {"primary": "-", "secondary": "-"}
        return {"primary": dns.findtext("primary","-"), "secondary": dns.findtext("secondary","-")}

    def get_syslog_direct(self) -> list:
        s = self._sys()
        log_el = s.find("syslog") if s else None
        if log_el is None: return []
        rows = []
        for entry in log_el.findall("entry"):
            rows.append({
                "Name":     entry.get("name","-"),
                "Server":   entry.findtext("server","-"),
                "Port":     entry.findtext("port","514"),
                "Format":   entry.findtext("format","BSD"),
                "Facility": entry.findtext("facility","-"),
            })
        return rows

    def get_scheduled_log_export(self) -> list:
        ls = self.dev.find("log-settings/scheduled-log-export") if self.dev else None
        if ls is None: return []
        rows = []
        for entry in ls.findall("entry"):
            at = entry.findtext("schedule/daily/at", "-")
            log_types = [c.tag for c in entry.findall("log-type/*")]
            rows.append({
                "Name":       entry.get("name","-"),
                "Protocol":   entry.findtext("destination-profile","-"),
                "Log Types":  ", ".join(log_types),
                "Start Time": at,
            })
        return rows
    def get_mgmt_services(self) -> dict:
        s = self._sys()
        svc = s.find("service") if s is not None else None
        def _s(tag):
            return (svc.findtext(tag) or "no") if svc is not None else "no"
        # Also check ping from permitted-ip or interface management
        ping_allowed = "yes"
        if s is not None:
            ping_el = s.find("service/disable-ssh")  # placeholder check
        return {
            "disable_telnet": _s("disable-telnet"),
            "disable_http":   _s("disable-http"),
            "disable_https":  _s("disable-https"),
            "disable_ssh":    _s("disable-ssh"),
        }

    def get_mgmt_ping(self) -> str:
        s = self._sys()
        if s is None: return "-"
        # Check permitted-ip or service settings for ping
        ping_val = s.findtext("service/ping-management", "yes")
        return ping_val

    def get_session_settings(self) -> dict:
        dc = self._dc()
        setting = dc.find("setting") if dc else None
        sess = setting.find("session") if setting else None
        if sess is None:
            return {}
        non_defaults = {}
        bool_fields = {
            "rematch-sessions": "Rematch Sessions",
            "ipv6-firewall": "IPv6 Firewalling",
            "jumbo-frame": "Jumbo Frame",
        }
        val_fields = {
            "icmpv6-token-bucket-size": "ICMPv6 Token Bucket Size",
            "global-mtu": "Global MTU",
            "packet-buffer-protection/enable": "Packet Buffer Protection",
        }
        for tag, label in bool_fields.items():
            val = sess.findtext(tag)
            if val and val not in ["-", ""]:
                non_defaults[label] = _tick(val)
        for tag, label in val_fields.items():
            val = sess.findtext(tag)
            if val and val not in ["-", ""]:
                non_defaults[label] = val
        return non_defaults

    def get_session_timeouts(self) -> dict:
        dc = self._dc()
        setting = dc.find("setting") if dc else None
        to = setting.find("session/timeout") if setting else None
        if to is None:
            return {}
        defaults = {"default":"60","tcp":"3600","udp":"30","icmp":"6",
                    "discard-default":"90","discard-tcp":"90","discard-udp":"60",
                    "scan":"5","tcp-handshake":"10","tcp-init":"5",
                    "tcp-half-closed":"120","tcp-time-wait":"15",
                    "unverified-rst":"30","captive-portal":"30"}
        tag_map = {"default":"Default (sec)","tcp":"TCP (sec)","udp":"UDP (sec)",
                   "icmp":"ICMP (sec)","discard-default":"Discard Default (sec)",
                   "discard-tcp":"Discard TCP (sec)","discard-udp":"Discard UDP (sec)",
                   "scan":"Scan (sec)","tcp-handshake":"TCP Handshake (sec)",
                   "tcp-init":"TCP Init (sec)","tcp-half-closed":"TCP Half Closed (sec)",
                   "tcp-time-wait":"TCP Time Wait (sec)","unverified-rst":"Unverified RST (sec)",
                   "captive-portal":"Captive Portal (sec)"}
        result = {}
        for tag, label in tag_map.items():
            val = to.findtext(tag)
            if val and val != defaults.get(tag, ""):
                result[label] = val
        return result

    def get_tcp_settings(self) -> dict:
        dc = self._dc()
        setting = dc.find("setting") if dc else None
        tcp = setting.find("tcp") if setting else None
        if tcp is None:
            return {}
        result = {}
        for tag, label in [("asymmetric-path","Asymmetric Path"),
                            ("drop-zero-flag","Drop Segments Without Flag"),
                            ("strip-mptcp-option","Strip MPTCP Option")]:
            val = tcp.findtext(tag)
            if val and val not in ["no","","bypass"]:
                result[label] = val
        return result

    def get_vpn_session_settings(self) -> dict:
        dc = self._dc()
        setting = dc.find("setting") if dc else None
        vpn = setting.find("ike") if setting else None
        if vpn is None:
            return {}
        return {
            "Cookie Activation Threshold": vpn.findtext("cookie-enable-threshold","-"),
            "Max Half Opened SA":          vpn.findtext("max-unauth-time","-"),
        }

    def get_dlp_settings(self) -> dict:
        dc = self._dc()
        setting = dc.find("setting") if dc else None
        dlp = setting.find("dlp") if setting else None
        if dlp is None:
            return {}
        file_dlp = dlp.find("file-dlp")
        non_file  = dlp.find("non-file-dlp")
        return {
            "file_dlp": {
                "Max Latency (sec)":     file_dlp.findtext("max-latency","-") if file_dlp else "-",
                "Action On Max Latency": file_dlp.findtext("action-on-latency","-") if file_dlp else "-",
                "Max File Size (MB)":    file_dlp.findtext("max-file-size","-") if file_dlp else "-",
                "Action On Max File":    file_dlp.findtext("action-on-max-file-size","-") if file_dlp else "-",
                "Log Not Scanned":       _tick(file_dlp.findtext("log-not-scanned","no")) if file_dlp else "",
            },
            "non_file_dlp": {
                "Enable Non-File DLP":   _tick(non_file.findtext("enable","no")) if non_file else "",
                "Max Latency (sec)":     non_file.findtext("max-latency","-") if non_file else "-",
                "Min Data Size (B)":     non_file.findtext("min-data-size","-") if non_file else "-",
                "Max Data Size (KB)":    non_file.findtext("max-data-size","-") if non_file else "-",
                "Log Not Scanned":       _tick(non_file.findtext("log-not-scanned","no")) if non_file else "",
            },
            "action_on_error": dlp.findtext("action-on-error","-") if dlp else "-",
        }

    def get_ha_active_passive(self) -> dict:
        dc = self._dc()
        ha = dc.find("high-availability") if dc else None
        grp = ha.find("group") if ha else None
        if grp is None:
            return {}
        ap = grp.find("mode/active-passive")
        if ap is None:
            return {}
        return {
            "Passive Link State":           ap.findtext("passive-link-state","auto"),
            "Monitor Fail Hold Down (min)": ap.findtext("monitor-fail-holddown","-"),
        }

    def get_iot_dhcp_ingestion(self) -> list:
        setting = self._setting()
        iot = setting.find("iot-security/dhcp-server-log-ingestion") if setting else None
        if iot is None:
            return []
        rows = []
        for e in iot.findall("entry"):
            srcs = [m.text for m in e.findall("source-address/member") if m.text]
            rows.append({
                "Name":    e.get("name","-"),
                "Address": ", ".join(srcs) if srcs else "-",
                "Enabled": _tick(e.findtext("enabled","yes")),
                "Type":    e.findtext("dhcp-server-type","-"),
                "Port":    e.findtext("port","-"),
                "Status":  "-",
            })
        return rows

    def get_data_redistribution(self) -> dict:
        setting = self._setting()
        dr = setting.find("data-redistribution") if setting else None
        if dr is None:
            return {}
        agents = []
        for e in dr.findall("redistribution-agent/entry"):
            agents.append({
                "Name":    e.get("name","-"),
                "Host":    e.findtext("address","-"),
                "Port":    e.findtext("port","-"),
                "Enabled": _tick(e.findtext("enabled","yes")),
            })
        cs = dr.find("collector-settings")
        collector = {
            "Collector Name": cs.findtext("host-id","-") if cs else "-",
            "Cert Profile":   cs.findtext("certificate-profile","-") if cs else "-",
            "Service Port":   cs.findtext("service-port","-") if cs else "-",
        }
        filt = dr.find("filter")
        inc_exc = []
        if filt:
            for m in filt.findall("include-network/member"):
                if m.text: inc_exc.append({"Type":"Include","Network":m.text})
            for m in filt.findall("exclude-network/member"):
                if m.text: inc_exc.append({"Type":"Exclude","Network":m.text})
        return {"agents":agents,"collector":collector,"inc_exc":inc_exc}

    def get_device_quarantines(self) -> list:
        dc = self._dc()
        sys_el = dc.find("system") if dc else None
        qlist = sys_el.find("device-quarantine/quarantine-list") if sys_el else None
        if qlist is None:
            return []
        rows = []
        for e in qlist.findall("entry"):
            rows.append({
                "Name":        e.get("name","-"),
                "Description": e.findtext("description","-"),
                "Timestamp":   e.findtext("timestamp","-"),
            })
        return rows

    def get_vm_info_sources(self) -> list:
        if self.dev is None: return []
        for path in ["server/vnmc-service-list","vm-info-source"]:
            el = self.dev.find(path)
            if el is not None:
                rows = []
                for e in el.findall("entry"):
                    src_type = "unknown"
                    for t in ["vmware-vcenter","aws-vpc","azure","google-compute"]:
                        if e.find(t) is not None:
                            src_type = t; break
                    rows.append({"Name":e.get("name","-"),"Enabled":_tick(e.findtext("enabled","yes")),
                                 "Type":src_type,"Status":"-"})
                return rows
        return []

    def get_ocsp_responders(self) -> list:
        shared = self._shared()
        el = shared.find("certificate-revocation-names") if shared else None
        if el is None: return []
        rows = []
        for e in el.findall("entry"):
            rows.append({"Name":e.get("name","-"),"Location":"shared",
                         "Hostname":e.findtext("ocsp/url","-"),
                         "Verify Cert":e.findtext("ocsp/verification-certificate","-")})
        return rows

    def get_scep_profiles(self) -> list:
        shared = self._shared()
        el = shared.find("scep") if shared else None
        if el is None: return []
        rows = []
        for e in el.findall("entry"):
            rows.append({"Name":e.get("name","-"),"Location":"shared",
                         "CA-Ident":e.findtext("ca-certificate","-"),
                         "Server URL":e.findtext("url","-")})
        return rows

    def get_ssl_decrypt_exclusions(self) -> list:
        shared = self._shared()
        for path in ["ssl-decrypt/ssl-exclude-cert","ssl-decrypt-exclude"]:
            el = shared.find(path) if shared else None
            if el is not None:
                rows = []
                for e in el.findall("entry"):
                    rows.append({"Hostname":e.findtext("hostname",e.get("name","-")),
                                 "Location":"shared","Description":e.findtext("description","-"),
                                 "Exclude":_tick(e.findtext("exclude","yes"))})
                return rows
        return []

    def get_ssh_service_profiles(self) -> list:
        net = self.dev.find("network") if self.dev else None
        if net is None: return []
        sp_el = net.find("ssh-service-profile")
        if sp_el is None: return []
        rows = []
        for e in sp_el.findall("entry"):
            sr = e.find("session-rekey")
            rows.append({"Name":e.get("name","-"),"Ciphers":_members_el(e.find("ciphers")),
                         "MAC":_members_el(e.find("mac")),"KEX":_members_el(e.find("kex")),
                         "Hostkey":_members_el(e.find("hostkey")),
                         "Data":sr.findtext("data","-") if sr else "-",
                         "Interval":sr.findtext("interval","-") if sr else "-",
                         "Packets":sr.findtext("packets","-") if sr else "-"})
        return rows

    def get_netflow_profiles(self) -> list:
        shared = self._shared()
        el = shared.find("server-profile/netflow") if shared else None
        if el is None: return []
        rows = []
        for entry in el.findall("entry"):
            tr = entry.find("template-refresh-rate")
            for s in entry.findall("server/entry"):
                rows.append({"Profile":entry.get("name","-"),"Server":s.get("name","-"),
                             "Host":s.findtext("host","-"),"Port":s.findtext("port","2055"),
                             "TRR Mins":tr.findtext("minutes","-") if tr else "-",
                             "TRR Pkt":tr.findtext("packets","-") if tr else "-",
                             "Act Timeout":entry.findtext("active-timeout","-")})
        return rows

    def get_scp_profiles(self) -> list:
        shared = self._shared()
        el = shared.find("server-profile/scp") if shared else None
        if el is None: return []
        rows = []
        for e in el.findall("entry"):
            rows.append({"Name":e.get("name","-"),"Server":e.findtext("server","-"),
                         "Port":e.findtext("port","22"),"Username":e.findtext("username","-")})
        return rows

    def get_tacacs_profiles(self) -> list:
        shared = self._shared()
        el = shared.find("server-profile/tacplus") if shared else None
        if el is None: return []
        rows = []
        for entry in el.findall("entry"):
            servers = [f"{s.get('name','-')}: {s.findtext('address','-')}:{s.findtext('port','49')}"
                       for s in entry.findall("server/entry")]
            rows.append({"Name":entry.get("name","-"),"Protocol":entry.findtext("protocol","-"),
                         "Servers":" | ".join(servers)})
        return rows

    def get_kerberos_profiles(self) -> list:
        shared = self._shared()
        el = shared.find("server-profile/kerberos") if shared else None
        if el is None: return []
        rows = []
        for entry in el.findall("entry"):
            servers = [f"{s.get('name','-')}: {s.findtext('server','-')}:{s.findtext('port','88')}"
                       for s in entry.findall("server/entry")]
            rows.append({"Name":entry.get("name","-"),"Realm":entry.findtext("realm","-"),
                         "Servers":" | ".join(servers)})
        return rows

    def get_saml_idp_profiles(self) -> list:
        shared = self._shared()
        el = shared.find("server-profile/saml-idp") if shared else None
        if el is None: return []
        rows = []
        for e in el.findall("entry"):
            rows.append({"Name":e.get("name","-"),"Location":"shared",
                         "IdP Cert":e.findtext("idp-certificate","-"),
                         "SSO URL":e.findtext("sso-url","-")})
        return rows

    def get_mfa_profiles(self) -> list:
        shared = self._shared()
        el = shared.find("server-profile/mfa") if shared else None
        if el is None: return []
        rows = []
        for e in el.findall("entry"):
            rows.append({"Name":e.get("name","-"),"Location":"shared",
                         "MFA Vendor":e.findtext("mfa-vendor","-"),
                         "Cert Profile":e.findtext("certificate-profile","-")})
        return rows

    def get_mgmt_services(self) -> dict:
        s = self._sys()
        svc = s.find("service") if s is not None else None
        def _s(tag):
            return (svc.findtext(tag) or "no") if svc is not None else "no"
        # Also check ping from permitted-ip or interface management
        ping_allowed = "yes"
        if s is not None:
            ping_el = s.find("service/disable-ssh")  # placeholder check
        return {
            "disable_telnet": _s("disable-telnet"),
            "disable_http":   _s("disable-http"),
            "disable_https":  _s("disable-https"),
            "disable_ssh":    _s("disable-ssh"),
        }

    def get_mgmt_ping(self) -> str:
        s = self._sys()
        if s is None: return "-"
        # Check permitted-ip or service settings for ping
        ping_val = s.findtext("service/ping-management", "yes")
        return ping_val

    def get_session_settings(self) -> dict:
        dc = self._dc()
        setting = dc.find("setting") if dc else None
        sess = setting.find("session") if setting else None
        if sess is None:
            return {}
        non_defaults = {}
        bool_fields = {
            "rematch-sessions": "Rematch Sessions",
            "ipv6-firewall": "IPv6 Firewalling",
            "jumbo-frame": "Jumbo Frame",
        }
        val_fields = {
            "icmpv6-token-bucket-size": "ICMPv6 Token Bucket Size",
            "global-mtu": "Global MTU",
            "packet-buffer-protection/enable": "Packet Buffer Protection",
        }
        for tag, label in bool_fields.items():
            val = sess.findtext(tag)
            if val and val not in ["-", ""]:
                non_defaults[label] = _tick(val)
        for tag, label in val_fields.items():
            val = sess.findtext(tag)
            if val and val not in ["-", ""]:
                non_defaults[label] = val
        return non_defaults

    def get_session_timeouts(self) -> dict:
        dc = self._dc()
        setting = dc.find("setting") if dc else None
        to = setting.find("session/timeout") if setting else None
        if to is None:
            return {}
        defaults = {"default":"60","tcp":"3600","udp":"30","icmp":"6",
                    "discard-default":"90","discard-tcp":"90","discard-udp":"60",
                    "scan":"5","tcp-handshake":"10","tcp-init":"5",
                    "tcp-half-closed":"120","tcp-time-wait":"15",
                    "unverified-rst":"30","captive-portal":"30"}
        tag_map = {"default":"Default (sec)","tcp":"TCP (sec)","udp":"UDP (sec)",
                   "icmp":"ICMP (sec)","discard-default":"Discard Default (sec)",
                   "discard-tcp":"Discard TCP (sec)","discard-udp":"Discard UDP (sec)",
                   "scan":"Scan (sec)","tcp-handshake":"TCP Handshake (sec)",
                   "tcp-init":"TCP Init (sec)","tcp-half-closed":"TCP Half Closed (sec)",
                   "tcp-time-wait":"TCP Time Wait (sec)","unverified-rst":"Unverified RST (sec)",
                   "captive-portal":"Captive Portal (sec)"}
        result = {}
        for tag, label in tag_map.items():
            val = to.findtext(tag)
            if val and val != defaults.get(tag, ""):
                result[label] = val
        return result

    def get_tcp_settings(self) -> dict:
        dc = self._dc()
        setting = dc.find("setting") if dc else None
        tcp = setting.find("tcp") if setting else None
        if tcp is None:
            return {}
        result = {}
        for tag, label in [("asymmetric-path","Asymmetric Path"),
                            ("drop-zero-flag","Drop Segments Without Flag"),
                            ("strip-mptcp-option","Strip MPTCP Option")]:
            val = tcp.findtext(tag)
            if val and val not in ["no","","bypass"]:
                result[label] = val
        return result

    def get_vpn_session_settings(self) -> dict:
        dc = self._dc()
        setting = dc.find("setting") if dc else None
        vpn = setting.find("ike") if setting else None
        if vpn is None:
            return {}
        return {
            "Cookie Activation Threshold": vpn.findtext("cookie-enable-threshold","-"),
            "Max Half Opened SA":          vpn.findtext("max-unauth-time","-"),
        }

    def get_dlp_settings(self) -> dict:
        dc = self._dc()
        setting = dc.find("setting") if dc else None
        dlp = setting.find("dlp") if setting else None
        if dlp is None:
            return {}
        file_dlp = dlp.find("file-dlp")
        non_file  = dlp.find("non-file-dlp")
        return {
            "file_dlp": {
                "Max Latency (sec)":     file_dlp.findtext("max-latency","-") if file_dlp else "-",
                "Action On Max Latency": file_dlp.findtext("action-on-latency","-") if file_dlp else "-",
                "Max File Size (MB)":    file_dlp.findtext("max-file-size","-") if file_dlp else "-",
                "Action On Max File":    file_dlp.findtext("action-on-max-file-size","-") if file_dlp else "-",
                "Log Not Scanned":       _tick(file_dlp.findtext("log-not-scanned","no")) if file_dlp else "",
            },
            "non_file_dlp": {
                "Enable Non-File DLP":   _tick(non_file.findtext("enable","no")) if non_file else "",
                "Max Latency (sec)":     non_file.findtext("max-latency","-") if non_file else "-",
                "Min Data Size (B)":     non_file.findtext("min-data-size","-") if non_file else "-",
                "Max Data Size (KB)":    non_file.findtext("max-data-size","-") if non_file else "-",
                "Log Not Scanned":       _tick(non_file.findtext("log-not-scanned","no")) if non_file else "",
            },
            "action_on_error": dlp.findtext("action-on-error","-") if dlp else "-",
        }

    def get_ha_active_passive(self) -> dict:
        dc = self._dc()
        ha = dc.find("high-availability") if dc else None
        grp = ha.find("group") if ha else None
        if grp is None:
            return {}
        ap = grp.find("mode/active-passive")
        if ap is None:
            return {}
        return {
            "Passive Link State":           ap.findtext("passive-link-state","auto"),
            "Monitor Fail Hold Down (min)": ap.findtext("monitor-fail-holddown","-"),
        }

    def get_iot_dhcp_ingestion(self) -> list:
        setting = self._setting()
        iot = setting.find("iot-security/dhcp-server-log-ingestion") if setting else None
        if iot is None:
            return []
        rows = []
        for e in iot.findall("entry"):
            srcs = [m.text for m in e.findall("source-address/member") if m.text]
            rows.append({
                "Name":    e.get("name","-"),
                "Address": ", ".join(srcs) if srcs else "-",
                "Enabled": _tick(e.findtext("enabled","yes")),
                "Type":    e.findtext("dhcp-server-type","-"),
                "Port":    e.findtext("port","-"),
                "Status":  "-",
            })
        return rows

    def get_data_redistribution(self) -> dict:
        setting = self._setting()
        dr = setting.find("data-redistribution") if setting else None
        if dr is None:
            return {}
        agents = []
        for e in dr.findall("redistribution-agent/entry"):
            agents.append({
                "Name":    e.get("name","-"),
                "Host":    e.findtext("address","-"),
                "Port":    e.findtext("port","-"),
                "Enabled": _tick(e.findtext("enabled","yes")),
            })
        cs = dr.find("collector-settings")
        collector = {
            "Collector Name": cs.findtext("host-id","-") if cs else "-",
            "Cert Profile":   cs.findtext("certificate-profile","-") if cs else "-",
            "Service Port":   cs.findtext("service-port","-") if cs else "-",
        }
        filt = dr.find("filter")
        inc_exc = []
        if filt:
            for m in filt.findall("include-network/member"):
                if m.text: inc_exc.append({"Type":"Include","Network":m.text})
            for m in filt.findall("exclude-network/member"):
                if m.text: inc_exc.append({"Type":"Exclude","Network":m.text})
        return {"agents":agents,"collector":collector,"inc_exc":inc_exc}

    def get_device_quarantines(self) -> list:
        dc = self._dc()
        sys_el = dc.find("system") if dc else None
        qlist = sys_el.find("device-quarantine/quarantine-list") if sys_el else None
        if qlist is None:
            return []
        rows = []
        for e in qlist.findall("entry"):
            rows.append({
                "Name":        e.get("name","-"),
                "Description": e.findtext("description","-"),
                "Timestamp":   e.findtext("timestamp","-"),
            })
        return rows

    def get_vm_info_sources(self) -> list:
        if self.dev is None: return []
        for path in ["server/vnmc-service-list","vm-info-source"]:
            el = self.dev.find(path)
            if el is not None:
                rows = []
                for e in el.findall("entry"):
                    src_type = "unknown"
                    for t in ["vmware-vcenter","aws-vpc","azure","google-compute"]:
                        if e.find(t) is not None:
                            src_type = t; break
                    rows.append({"Name":e.get("name","-"),"Enabled":_tick(e.findtext("enabled","yes")),
                                 "Type":src_type,"Status":"-"})
                return rows
        return []

    def get_ocsp_responders(self) -> list:
        shared = self._shared()
        el = shared.find("certificate-revocation-names") if shared else None
        if el is None: return []
        rows = []
        for e in el.findall("entry"):
            rows.append({"Name":e.get("name","-"),"Location":"shared",
                         "Hostname":e.findtext("ocsp/url","-"),
                         "Verify Cert":e.findtext("ocsp/verification-certificate","-")})
        return rows

    def get_scep_profiles(self) -> list:
        shared = self._shared()
        el = shared.find("scep") if shared else None
        if el is None: return []
        rows = []
        for e in el.findall("entry"):
            rows.append({"Name":e.get("name","-"),"Location":"shared",
                         "CA-Ident":e.findtext("ca-certificate","-"),
                         "Server URL":e.findtext("url","-")})
        return rows

    def get_ssl_decrypt_exclusions(self) -> list:
        shared = self._shared()
        for path in ["ssl-decrypt/ssl-exclude-cert","ssl-decrypt-exclude"]:
            el = shared.find(path) if shared else None
            if el is not None:
                rows = []
                for e in el.findall("entry"):
                    rows.append({"Hostname":e.findtext("hostname",e.get("name","-")),
                                 "Location":"shared","Description":e.findtext("description","-"),
                                 "Exclude":_tick(e.findtext("exclude","yes"))})
                return rows
        return []

    def get_ssh_service_profiles(self) -> list:
        net = self.dev.find("network") if self.dev else None
        if net is None: return []
        sp_el = net.find("ssh-service-profile")
        if sp_el is None: return []
        rows = []
        for e in sp_el.findall("entry"):
            sr = e.find("session-rekey")
            rows.append({"Name":e.get("name","-"),"Ciphers":_members_el(e.find("ciphers")),
                         "MAC":_members_el(e.find("mac")),"KEX":_members_el(e.find("kex")),
                         "Hostkey":_members_el(e.find("hostkey")),
                         "Data":sr.findtext("data","-") if sr else "-",
                         "Interval":sr.findtext("interval","-") if sr else "-",
                         "Packets":sr.findtext("packets","-") if sr else "-"})
        return rows

    def get_netflow_profiles(self) -> list:
        shared = self._shared()
        el = shared.find("server-profile/netflow") if shared else None
        if el is None: return []
        rows = []
        for entry in el.findall("entry"):
            tr = entry.find("template-refresh-rate")
            for s in entry.findall("server/entry"):
                rows.append({"Profile":entry.get("name","-"),"Server":s.get("name","-"),
                             "Host":s.findtext("host","-"),"Port":s.findtext("port","2055"),
                             "TRR Mins":tr.findtext("minutes","-") if tr else "-",
                             "TRR Pkt":tr.findtext("packets","-") if tr else "-",
                             "Act Timeout":entry.findtext("active-timeout","-")})
        return rows

    def get_scp_profiles(self) -> list:
        shared = self._shared()
        el = shared.find("server-profile/scp") if shared else None
        if el is None: return []
        rows = []
        for e in el.findall("entry"):
            rows.append({"Name":e.get("name","-"),"Server":e.findtext("server","-"),
                         "Port":e.findtext("port","22"),"Username":e.findtext("username","-")})
        return rows

    def get_tacacs_profiles(self) -> list:
        shared = self._shared()
        el = shared.find("server-profile/tacplus") if shared else None
        if el is None: return []
        rows = []
        for entry in el.findall("entry"):
            servers = [f"{s.get('name','-')}: {s.findtext('address','-')}:{s.findtext('port','49')}"
                       for s in entry.findall("server/entry")]
            rows.append({"Name":entry.get("name","-"),"Protocol":entry.findtext("protocol","-"),
                         "Servers":" | ".join(servers)})
        return rows

    def get_kerberos_profiles(self) -> list:
        shared = self._shared()
        el = shared.find("server-profile/kerberos") if shared else None
        if el is None: return []
        rows = []
        for entry in el.findall("entry"):
            servers = [f"{s.get('name','-')}: {s.findtext('server','-')}:{s.findtext('port','88')}"
                       for s in entry.findall("server/entry")]
            rows.append({"Name":entry.get("name","-"),"Realm":entry.findtext("realm","-"),
                         "Servers":" | ".join(servers)})
        return rows

    def get_saml_idp_profiles(self) -> list:
        shared = self._shared()
        el = shared.find("server-profile/saml-idp") if shared else None
        if el is None: return []
        rows = []
        for e in el.findall("entry"):
            rows.append({"Name":e.get("name","-"),"Location":"shared",
                         "IdP Cert":e.findtext("idp-certificate","-"),
                         "SSO URL":e.findtext("sso-url","-")})
        return rows

    def get_mfa_profiles(self) -> list:
        shared = self._shared()
        el = shared.find("server-profile/mfa") if shared else None
        if el is None: return []
        rows = []
        for e in el.findall("entry"):
            rows.append({"Name":e.get("name","-"),"Location":"shared",
                         "MFA Vendor":e.findtext("mfa-vendor","-"),
                         "Cert Profile":e.findtext("certificate-profile","-")})