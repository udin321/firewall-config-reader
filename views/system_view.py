import streamlit as st
import pandas as pd


def _show_table(rows, empty_msg="Not configured"):
    if not rows:
        st.info(empty_msg)
        return
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _toggle(label, value):
    on = str(value).lower() in ["enable", "on", "1", "true"]
    color = "#2ecc71" if on else "#ccc"
    bg    = "#e8f8f0" if on else "#f5f5f5"
    text  = "ON" if on else "OFF"
    st.markdown(
        f'<div style="display:flex;align-items:center;justify-content:space-between;'
        f'background:{bg};border-radius:8px;padding:8px 14px;margin:4px 0;">'
        f'<span style="font-size:13px">{label}</span>'
        f'<span style="background:{color};color:white;padding:2px 12px;'
        f'border-radius:12px;font-size:12px;font-weight:bold">{text}</span></div>',
        unsafe_allow_html=True
    )


def _scope_selector(current_scope):
    """Display password scope as styled toggle buttons."""
    scopes = [
        ("off",          "Off"),
        ("admin",        "Admin"),
        ("ipsec",        "IPSec"),
        ("admin-ipsec",  "Both"),
    ]
    cols = st.columns(len(scopes))
    for col, (val, label) in zip(cols, scopes):
        is_sel = current_scope.lower() == val
        bg  = "#2c3e50" if is_sel else "#ecf0f1"
        fg  = "white"  if is_sel else "#666"
        col.markdown(
            f'<div style="background:{bg};color:{fg};border-radius:8px;padding:10px;'
            f'text-align:center;font-weight:{"bold" if is_sel else "normal"};font-size:13px">'
            f'{label}{"  ✓" if is_sel else ""}</div>',
            unsafe_allow_html=True
        )


def render_system(parser):
    st.subheader("System")

    tab_admin, tab_profile, tab_settings, tab_ha, tab_snmp = st.tabs([
        "Administrators", "Admin Profiles", "Settings", "HA", "SNMP"
    ])

    with tab_admin:
        st.markdown("#### Administrators")
        rows = parser.parse_admins()
        if not rows:
            st.info("No administrators configured.")
        else:
            rows = sorted(rows, key=lambda x: (0 if x["Profile"] == "super_admin" else 1, x["Name"]))
            df = pd.DataFrame(rows)
            def hl_admin(row):
                if row.get("Profile") == "super_admin":
                    return ["background-color:#fef9e7"] * len(row)
                return [""] * len(row)
            st.dataframe(df.style.apply(hl_admin, axis=1), use_container_width=True, hide_index=True)

    with tab_profile:
        st.markdown("#### Admin Profiles")
        profiles = parser.parse_accprofiles()
        if not profiles:
            st.info("No admin profiles configured.")
        else:
            perm_cols = ["Security Fabric","FortiView","User & Device","Firewall",
                         "Log & Report","Network","System","Security Profile","VPN","WiFi & Switch"]
            COLOURS = {"Read/Write": "#27ae60", "Read": "#2980b9", "None": "#95a5a6"}
            for prof in profiles:
                with st.expander(f"**{prof['name']}**", expanded=False):
                    if prof.get("comments"):
                        st.caption(prof["comments"])
                    cols = st.columns(len(perm_cols))
                    for col, perm in zip(cols, perm_cols):
                        val = prof.get(perm, "None")
                        bg  = COLOURS.get(val, "#95a5a6")
                        col.markdown(
                            f'<div style="text-align:center;padding:6px 2px">'
                            f'<div style="font-size:10px;color:#666;margin-bottom:4px">{perm}</div>'
                            f'<span style="background:{bg};color:white;padding:3px 8px;'
                            f'border-radius:8px;font-size:11px;font-weight:bold">{val}</span></div>',
                            unsafe_allow_html=True
                        )

    with tab_settings:
        s = parser.parse_system_settings()
        if not s:
            st.info("No system settings found.")
        else:
            TIMEZONES = {
                "57": "Asia/Kuala_Lumpur (UTC+8)", "0": "UTC",
                "12": "UTC-5 (EST)", "29": "UTC+0 (London)", "28": "UTC+1 (Paris)",
            }
            st.markdown("#### Device Identity")
            c1, c2, c3 = st.columns(3)
            c1.metric("Hostname", s.get("hostname", "-"))
            c2.metric("Alias",    s.get("alias", "-"))
            c3.metric("Theme",    s.get("theme", "-").capitalize())

            st.divider()
            st.markdown("#### Time Settings")
            tz_display = TIMEZONES.get(s.get("timezone", "0"), f"TZ {s.get('timezone','0')}")
            st.markdown(f"**Timezone:** `{tz_display}`")
            ntp = s.get("ntp", {})
            if ntp:
                ntp_servers  = ntp.get("servers", [])
                server_display = ", ".join(ntp_servers) if ntp_servers else "FortiGuard"
                is_fortiguard  = any(sv in ["FortiGuard","96.45.33.80","96.45.33.81"] for sv in ntp_servers) if ntp_servers else True
                c1, c2 = st.columns(2)
                c1.markdown(
                    f'<div style="background:{"#e8f8f0" if is_fortiguard else "#eaf4fb"};border-radius:10px;padding:12px;">'
                    f'<div style="font-size:11px;color:#666">NTP Server</div>'
                    f'<div style="font-weight:bold;color:#2c3e50">{"FortiGuard" if is_fortiguard else "Custom"}</div>'
                    f'<div style="font-size:11px;color:#888;margin-top:4px">{server_display}</div></div>',
                    unsafe_allow_html=True
                )
                c2.metric("Sync Interval", f"{ntp.get('interval','60')} min")

            st.divider()
            st.markdown("#### Administration")
            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("HTTP Port",   s.get("http_port", "80"))
            c2.metric("HTTPS Port",  s.get("https_port", "443"))
            c3.metric("SSH Port",    s.get("ssh_port", "22"))
            c4.metric("Telnet Port", s.get("telnet_port", "23"))
            c5.metric("Idle Timeout", f"{s.get('idle_timeout','5')} min")
            _toggle("Redirect HTTP to HTTPS", s.get("http_redirect", "enable"))

            st.divider()
            st.markdown("#### Single Sign-On")
            _toggle("FortiCloud SSO", s.get("forticloud_sso", "disable"))

            st.divider()
            st.markdown("#### Password Policy")
            passwd_on = s.get("passwd_policy", "disable") == "enable"
            _toggle("Password Policy Enabled", s.get("passwd_policy", "disable"))
            st.markdown("**Password Scope**")
            # Always show scope selector; if policy is off, scope is "off"
            scope_display = s.get("passwd_scope", "off") if passwd_on else "off"
            _scope_selector(scope_display)

            st.divider()
            st.markdown("#### Workflow Management")
            mode = s.get("workflow_mode", "automatic").capitalize()
            is_auto = mode.lower() == "automatic"
            st.markdown(
                f'<div style="background:{"#e8f8f0" if is_auto else "#fef9e7"};border-radius:10px;padding:12px;margin-top:4px">'
                f'<div style="font-size:12px;color:#666">Configuration Saved Mode</div>'
                f'<div style="font-size:16px;font-weight:bold;color:#2c3e50;margin-top:4px">{mode}</div></div>',
                unsafe_allow_html=True
            )

    with tab_ha:
        st.markdown("#### High Availability")
        ha   = parser.parse_ha_config()
        mode = ha.get("mode", "standalone")
        if mode == "standalone":
            st.markdown(
                '<div style="background:#f8f9fa;border-radius:12px;padding:20px;text-align:center">'
                '<div style="font-size:32px">🖥️</div>'
                '<div style="font-size:18px;font-weight:bold;color:#2c3e50;margin-top:8px">Standalone</div>'
                '<div style="color:#666;font-size:13px">No HA cluster configured</div></div>',
                unsafe_allow_html=True
            )
        else:
            mode_label = "Active-Passive" if mode == "a-p" else "Active-Active"
            mode_color = "#2ecc71" if mode == "a-p" else "#3498db"
            st.markdown(
                f'<div style="background:{mode_color}15;border:2px solid {mode_color};'
                f'border-radius:12px;padding:16px;margin-bottom:16px">'
                f'<div style="font-size:20px;font-weight:bold;color:{mode_color}">{mode_label}</div></div>',
                unsafe_allow_html=True
            )
            c1, c2 = st.columns(2)
            c1.metric("Device Priority", ha.get("priority", "-"))
            c2.metric("Override",        ha.get("override", "-").capitalize())
            st.markdown("##### Cluster Settings")
            c3, c4 = st.columns(2)
            c3.metric("Group ID",   ha.get("group_id", "-"))
            c4.metric("Group Name", ha.get("group_name", "-"))
            _toggle("Session Pickup", ha.get("session_pickup", "disable"))
            st.markdown(f"**Heartbeat Interfaces:** `{ha.get('hbdev', '-')}`")
            monitors = ha.get("monitor", [])
            if monitors:
                st.markdown(f"**Monitor Interfaces:** {', '.join(monitors)}")
            mgmt = ha.get("mgmt_reserved", [])
            st.divider()
            st.markdown("##### Management Interface Reservation")
            if mgmt:
                _toggle("Management Interface Reserved", "enable")
                st.dataframe(pd.DataFrame(mgmt), use_container_width=True, hide_index=True)
            else:
                _toggle("Management Interface Reserved", "disable")

    with tab_snmp:
        st.markdown("#### SNMP")
        snmp    = parser.parse_snmp()
        sysinfo = snmp.get("sysinfo", {})
        st.markdown("##### System Information")
        _toggle("SNMP Agent", sysinfo.get("status", "disable"))
        if sysinfo.get("status", "disable") == "enable":
            c1, c2, c3 = st.columns(3)
            c1.metric("Description", sysinfo.get("description", "-"))
            c2.metric("Location",    sysinfo.get("location", "-"))
            c3.metric("Contact",     sysinfo.get("contact", "-"))
        st.divider()
        st.markdown("##### SNMPv1/v2c Communities")
        _show_table(snmp.get("communities", []), "No SNMP v1/v2c communities configured.")
        st.divider()
        st.markdown("##### SNMPv3 Users")
        _show_table(snmp.get("v3_users", []), "No SNMP v3 users configured.")


def render_log_report(parser):
    st.subheader("Log & Report")
    tab_log_set, tab_threat = st.tabs(["Log Settings", "Threat Weight"])

    with tab_log_set:
        log = parser.parse_log_settings()
        st.markdown("#### Global Settings — UUIDs in Traffic Logs")
        _toggle("Address", log.get("fwpolicy_implicit", "disable"))
        st.divider()
        st.markdown("#### Log Settings")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Event Logging**")
            _toggle("Local Traffic - Allow",          log.get("local_in_allow", "disable"))
            st.markdown("")
            _toggle("Local Traffic - Deny Unicast",   log.get("local_in_deny_uni", "disable"))
            st.markdown("")
            _toggle("Local Traffic - Deny Broadcast", log.get("local_in_deny_brd", "disable"))
        with col2:
            st.markdown("**Storage**")
            _toggle("Memory Log",      log.get("memory_log", "disable"))
            st.markdown("")
            _toggle("Syslog Logging",  log.get("syslog_enabled", "disable"))
        st.divider()
        st.markdown("#### GUI Preferences")
        _toggle("Resolve Hostnames",            log.get("resolve_hosts", "disable"))
        st.markdown("")
        _toggle("Resolve Unknown Applications", log.get("resolve_apps", "disable"))

    with tab_threat:
        tw = parser.parse_threat_weight()
        if not tw:
            st.info("No threat weight configuration found.")
            return

        _toggle("Log Threat Weight", tw.get("status", "enable"))
        st.divider()

        LEVEL_COLOURS = {
            "Off": "#95a5a6", "Low": "#3498db",
            "Medium": "#f39c12", "High": "#e67e22", "Critical": "#e74c3c"
        }

        def level_card(label, level, levels=None):
            if levels is None:
                levels = ["Off", "Low", "Medium", "High", "Critical"]
            badges = ""
            for lv in levels:
                bg = LEVEL_COLOURS.get(lv, "#95a5a6")
                sel_style = "border:2px solid #333;transform:scale(1.1);" if lv == level else "opacity:0.35;"
                badges += (
                    f'<span style="background:{bg};color:white;padding:3px 9px;'
                    f'border-radius:10px;font-size:11px;font-weight:bold;'
                    f'margin:0 2px;{sel_style}">{lv}</span>'
                )
            return (
                f'<div style="display:flex;align-items:center;justify-content:space-between;'
                f'padding:7px 10px;border-radius:8px;margin:3px 0;background:#fafafa;border:1px solid #eee">'
                f'<span style="font-size:13px;min-width:220px">{label}</span><div>{badges}</div></div>'
            )

        st.markdown("#### Application Protection")
        for name, level in tw.get("app_weights", {}).items():
            st.markdown(level_card(name, level), unsafe_allow_html=True)

        st.divider()
        st.markdown("#### Intrusion Prevention")
        st.markdown(level_card("Detection Severity", tw.get("ips_detect", "Medium")), unsafe_allow_html=True)

        st.divider()
        st.markdown("#### Botnet Communication")
        st.markdown(level_card("Botnet Connection", tw.get("botnet", "Medium")), unsafe_allow_html=True)

        st.divider()
        st.markdown("#### Malware Detection")
        for label in ["Virus Detected", "File Blocked", "Blocked Command", "Oversized File"]:
            st.markdown(level_card(label, tw.get("malware", "Medium")), unsafe_allow_html=True)

        st.divider()
        st.markdown("#### Packet Based Inspection")
        st.markdown(level_card("Blocked Connection", tw.get("blocked_conn", "Medium")), unsafe_allow_html=True)
        st.markdown(level_card("Failed Connection",  tw.get("failed_conn", "Medium")),  unsafe_allow_html=True)

        st.divider()
        st.markdown("#### Web Activity")
        for name, level in tw.get("web_weights", {}).items():
            st.markdown(level_card(name, level), unsafe_allow_html=True)
        if not tw.get("web_weights"):
            st.markdown(level_card("Blocked URLs", tw.get("url_block", "Medium")), unsafe_allow_html=True)

        st.divider()
        st.markdown("#### Risk Level Values")
        risk_cols = st.columns(4)
        risks = [("Low","#3498db","5"),("Medium","#f39c12","10"),("High","#e67e22","30"),("Critical","#e74c3c","50")]
        for col, (label, color, val) in zip(risk_cols, risks):
            col.markdown(
                f'<div style="background:{color};color:white;border-radius:10px;padding:12px;text-align:center">'
                f'<div style="font-size:20px;font-weight:bold">{val}</div>'
                f'<div style="font-size:12px;margin-top:4px">{label}</div></div>',
                unsafe_allow_html=True
            )
