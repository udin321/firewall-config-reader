"""Palo Alto Device views – full rebuild with all enhancements."""

import streamlit as st
import pandas as pd
from parsers.palo_device import PaloDeviceParser


def _show(rows, empty="Not configured.", key=None):
    if not rows:
        st.info(empty)
        return
    df = pd.DataFrame(rows)
    kw = {"use_container_width": True, "hide_index": True}
    if key:
        kw["key"] = key
    st.dataframe(df, **kw)
    st.caption(f"Total: {len(rows)} entries")


def _infobox(title, data: dict, icon="ℹ️"):
    if not data:
        return
    st.markdown(f"**{icon} {title}**")
    items = []
    for k, v in data.items():
        color = ""
        if v == "✓":
            color = "color:#27ae60;font-weight:bold"
        elif str(v) in ["-", "no", "None", ""]:
            color = "color:#aaa"
        items.append(
            f'<div style="display:flex;justify-content:space-between;padding:4px 10px;'
            f'background:#f8f9fa;border-radius:6px;margin:2px 0">'
            f'<span style="font-size:12px;color:#555">{k}</span>'
            f'<span style="font-size:12px;{color};max-width:60%;text-align:right">{v}</span></div>'
        )
    st.markdown("\n".join(items), unsafe_allow_html=True)
    st.markdown("")


def render_pa_device(parser: PaloDeviceParser):
    st.markdown("### ⚙️ Device")

    tabs = st.tabs(
        [
            "Setup",
            "High Availability",
            "Password Profiles",
            "Administrators",
            "Admin Roles",
            "Auth Profiles",
            "Auth Sequences",
            "User Identification",
            "IoT Security",
            "Data Redistribution",
            "Device Quarantines",
            "VM Info Source",
            "Certificate Mgmt",
            "Log Settings",
            "Server Profiles",
            "Local User DB",
            "Scheduled Log Export",
        ]
    )

    # ── 1. SETUP ───────────────────────────────────────────────
    with tabs[0]:
        st.markdown("#### ⚙️ Setup")
        setup_sub = st.tabs(["Management", "Services", "Interface", "Session", "DLP"])

        with setup_sub[0]:
            c1, c2 = st.columns(2)
            with c1:
                _infobox("General Settings", parser.get_general_settings(), "🖥️")
                _infobox("Panorama Settings", parser.get_panorama_settings(), "☁️")
                _infobox("Authentication", parser.get_auth_settings(), "🔐")
            with c2:
                _infobox("Logging & Reporting", parser.get_logging_settings(), "📜")
                pc = parser.get_password_complexity()
                _infobox("Min Password Complexity", pc, "🔑")

        with setup_sub[1]:
            c1, c2 = st.columns(2)
            with c1:
                _infobox("Services", parser.get_services_config(), "🌐")
            with c2:
                routes = parser.get_service_routes()
                if routes:
                    st.markdown("**Service Routes (Custom)**")
                    _show(routes, key="svc_routes")
                else:
                    st.info("Service routes: using default.")

        with setup_sub[2]:
            mgmt = parser.get_mgmt_interface()
            if mgmt:
                c1, c2, c3 = st.columns(3)
                c1.metric("IP Address", mgmt.get("IP Address", "-"))
                c2.metric("Netmask", mgmt.get("Netmask", "-"))
                c3.metric("Default Gateway", mgmt.get("Default Gateway", "-"))
            st.markdown("**Management Services**")
            svc = parser.get_mgmt_services()
            # Check ping permission from system/service
            sys_el = parser._sys()
            ping_disabled = "no"
            if sys_el is not None:
                ping_disabled = sys_el.findtext("service/disable-ping", "no")
            ping_state = "Disabled" if ping_disabled == "yes" else "Enabled"

            svc_rows = [
                {
                    "Service": "Telnet",
                    "State": (
                        "Disabled"
                        if svc.get("disable_telnet", "no") == "yes"
                        else "Enabled"
                    ),
                },
                {
                    "Service": "HTTP",
                    "State": (
                        "Disabled"
                        if svc.get("disable_http", "no") == "yes"
                        else "Enabled"
                    ),
                },
                {
                    "Service": "HTTPS",
                    "State": (
                        "Disabled"
                        if svc.get("disable_https", "no") == "yes"
                        else "Enabled"
                    ),
                },
                {
                    "Service": "SSH",
                    "State": (
                        "Disabled"
                        if svc.get("disable_ssh", "no") == "yes"
                        else "Enabled"
                    ),
                },
                {"Service": "Ping", "State": ping_state},
            ]
            df_svc = pd.DataFrame(svc_rows)

            def hl_svc(row):
                return [
                    (
                        "background-color:#e8f8f0"
                        if row["State"] == "Enabled"
                        else "background-color:#fdecea"
                    )
                ] * len(row)

            st.dataframe(
                df_svc.style.apply(hl_svc, axis=1),
                use_container_width=True,
                hide_index=True,
            )

        with setup_sub[3]:
            st.markdown("##### 🔄 Session Settings (Non-Default Only)")
            ss = parser.get_session_settings()
            if ss:
                _infobox("Session Settings", ss)
            else:
                st.info("All session settings at default.")
            st.markdown("##### ⏱️ Session Timeouts (Non-Default)")
            to = parser.get_session_timeouts()
            if to:
                _infobox("Timeouts", to)
            else:
                st.info("All timeouts at default values.")
            st.markdown("##### 🔌 TCP Settings (Non-Default)")
            tcp = parser.get_tcp_settings()
            if tcp:
                _infobox("TCP", tcp)
            else:
                st.info("All TCP settings at default.")
            st.markdown("##### 🔐 VPN Session Settings")
            _infobox("VPN Sessions", parser.get_vpn_session_settings())

        with setup_sub[4]:
            st.markdown("##### 🔒 DLP Settings")
            dlp = parser.get_dlp_settings()
            if dlp:
                c1, c2, c3 = st.columns(3)
                with c1:
                    _infobox("File-Based DLP", dlp.get("file_dlp", {}))
                with c2:
                    _infobox("Non-File DLP", dlp.get("non_file_dlp", {}))
                with c3:
                    _infobox(
                        "DLP Settings",
                        {"Action on Error": dlp.get("action_on_error", "-")},
                    )
            else:
                st.info("DLP not configured.")

    # ── 2. HIGH AVAILABILITY ───────────────────────────────────
    with tabs[1]:
        st.markdown("#### 🔗 High Availability")
        ha_sub = st.tabs(["General", "HA Communication", "Link & Path Monitoring"])

        with ha_sub[0]:
            ha = parser.get_ha_general()
            enabled = ha.get("enabled", "no") == "yes"
            color = "#27ae60" if enabled else "#e74c3c"
            st.markdown(
                f'<div style="background:{color}15;border:2px solid {color};border-radius:12px;'
                f'padding:14px;margin-bottom:16px"><span style="font-size:16px;font-weight:bold;color:{color}">'
                f'{"HA Enabled" if enabled else "Standalone"}</span></div>',
                unsafe_allow_html=True,
            )
            if enabled:
                c1, c2, c3 = st.columns(3)
                with c1:
                    _infobox(
                        "Setup",
                        {
                            "Group ID": ha.get("group_id", "-"),
                            "Mode": ha.get("mode", "-"),
                            "Config Sync": ha.get("config_sync", "no"),
                            "Peer HA1 IP": ha.get("peer_ha1_ip", "-"),
                            "Backup Peer": ha.get("backup_peer", "-"),
                        },
                    )
                with c2:
                    _infobox(
                        "Election Settings",
                        {
                            "Device Priority": ha.get("priority", "-"),
                            "Preemptive": ha.get("preemptive", "no"),
                        },
                    )
                with c3:
                    ap = parser.get_ha_active_passive()
                    _infobox(
                        "Active/Passive", ap if ap else {"Note": "Not active-passive"}
                    )

        with ha_sub[1]:
            ha_intfs = parser.get_ha_interfaces()
            if ha_intfs:
                c1, c2 = st.columns(2)
                with c1:
                    _infobox("HA1", ha_intfs.get("ha1", {}), "🔵")
                    _infobox("HA1 Backup", ha_intfs.get("ha1_backup", {}), "🔵")
                with c2:
                    _infobox("HA2", ha_intfs.get("ha2", {}), "🟢")
                    _infobox("HA2 Backup", ha_intfs.get("ha2_backup", {}), "🟢")
            else:
                st.info("HA not configured.")

        with ha_sub[2]:
            lpm = parser.get_ha_link_path_monitoring()
            if lpm:
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(
                        f"**Link Monitoring:** Enabled={lpm.get('link_enabled','no')} | Fail Cond={lpm.get('link_fail_cond','any')}"
                    )
                    _show(lpm.get("link_groups", []), "No link groups.", key="lm_grp")
                with c2:
                    st.markdown(
                        f"**Path Monitoring:** Enabled={lpm.get('path_enabled','no')} | Fail Cond={lpm.get('path_fail_cond','any')}"
                    )
                    _show(lpm.get("path_groups", []), "No path groups.", key="pm_grp")
            else:
                st.info("Link/path monitoring not configured.")

    # ── 3. PASSWORD PROFILES ───────────────────────────────────
    with tabs[2]:
        st.markdown("#### 🔑 Password Profiles")
        _show(parser.get_password_profiles(), "No password profiles.", key="pp")

    # ── 4. ADMINISTRATORS ──────────────────────────────────────
    with tabs[3]:
        st.markdown("#### 👤 Administrators")
        rows = parser.get_admins()
        if rows:
            df = pd.DataFrame(rows)

            def hl_admin(row):
                if "superuser" in str(row.get("Role", "")).lower():
                    return ["background-color:#fef9e7"] * len(row)
                return [""] * len(row)

            st.dataframe(
                df.style.apply(hl_admin, axis=1),
                use_container_width=True,
                hide_index=True,
            )
            st.caption(f"Total: {len(rows)} administrators")
        else:
            st.info("No administrators configured.")

    # ── 5. ADMIN ROLES ─────────────────────────────────────────
    with tabs[4]:
        st.markdown("#### 🎭 Admin Roles")
        _show(parser.get_admin_roles(), "No custom admin roles.", key="ar")

    # ── 6. AUTH PROFILES ──────────────────────────────────────
    with tabs[5]:
        st.markdown("#### 🔐 Authentication Profiles")
        _show(parser.get_auth_profiles(), "No authentication profiles.", key="ap")

    # ── 7. AUTH SEQUENCES ─────────────────────────────────────
    with tabs[6]:
        st.markdown("#### 🔗 Authentication Sequences")
        _show(parser.get_auth_sequences(), "No authentication sequences.", key="aseq")

    # ── 8. USER IDENTIFICATION ────────────────────────────────
    with tabs[7]:
        st.markdown("#### 👥 User Identification")
        uid = parser.get_user_id_info()
        if not uid:
            st.info("User ID not configured.")
        else:
            uid_sub = st.tabs(
                [
                    "User Mapping",
                    "Terminal Server Agents",
                    "Group Mapping",
                    "Auth Portal",
                ]
            )
            with uid_sub[0]:
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("##### Server Monitoring")
                    _show(
                        uid.get("server_monitoring", []),
                        "No server monitoring.",
                        key="uid_sm",
                    )
                with c2:
                    st.markdown("##### Include/Exclude Networks")
                    _show(uid.get("inc_exc", []), "No inc/exc networks.", key="uid_ie")
                st.markdown(
                    f"**User-ID Cert Profile:** `{uid.get('uid_cert_profile','-')}`"
                )
                ts = uid.get("trusted_src", [])
                if ts:
                    st.markdown(f"**Trusted Sources:** {', '.join(ts)}")
            with uid_sub[1]:
                _show(
                    uid.get("ts_agents", []),
                    "No terminal server agents.",
                    key="uid_tsa",
                )
            with uid_sub[2]:
                _show(uid.get("group_mappings", []), "No group mappings.", key="uid_gm")
            with uid_sub[3]:
                ap = uid.get("auth_portal", {})
                if ap:
                    _infobox("Authentication Portal", ap)
                else:
                    st.info("Auth portal not configured.")

    # ── 9. IOT SECURITY ───────────────────────────────────────
    with tabs[8]:
        st.markdown("#### 📡 IoT Security — DHCP Server Log Ingestion")
        _show(parser.get_iot_dhcp_ingestion(), "No IoT DHCP log ingestion.", key="iot")

    # ── 10. DATA REDISTRIBUTION ───────────────────────────────
    with tabs[9]:
        st.markdown("#### 🔄 Data Redistribution")
        dr = parser.get_data_redistribution()
        if dr:
            st.markdown("##### Agents")
            _show(dr.get("agents", []), "No redistribution agents.", key="dr_agents")
            st.markdown("##### Collector Settings")
            _infobox("Collector", dr.get("collector", {}))
            st.markdown("##### Include/Exclude Networks")
            _show(dr.get("inc_exc", []), "No filter networks.", key="dr_ie")
        else:
            st.info("Data Redistribution not configured.")

    # ── 11. DEVICE QUARANTINES ────────────────────────────────
    with tabs[10]:
        st.markdown("#### 🚫 Device Quarantines")
        _show(parser.get_device_quarantines(), "No quarantined devices.", key="dq")

    # ── 12. VM INFORMATION SOURCE ─────────────────────────────
    with tabs[11]:
        st.markdown("#### ☁️ VM Information Source")
        _show(parser.get_vm_info_sources(), "No VM information sources.", key="vm")

    # ── 13. CERTIFICATE MANAGEMENT ─────────────────────────────
    with tabs[12]:
        st.markdown("#### 🔏 Certificate Management")
        cert_sub = st.tabs(
            [
                "Certificates",
                "SSL/TLS Profiles",
                "Cert Profiles",
                "OCSP Responder",
                "SCEP",
                "SSL Decrypt Exclusions",
                "SSH Service Profiles",
            ]
        )
        with cert_sub[0]:
            rows = parser.get_certificates()
            if rows:
                df = pd.DataFrame(rows)

                def hl_cert(row):
                    s = str(row.get("Status", "")).lower()
                    if s == "expired":
                        return ["background-color:#fdecea"] * len(row)
                    if s == "expiring soon":
                        return ["background-color:#fff3cd"] * len(row)
                    if s == "valid":
                        return ["background-color:#e8f8f0"] * len(row)
                    return [""] * len(row)

                st.dataframe(
                    df.style.apply(hl_cert, axis=1),
                    use_container_width=True,
                    hide_index=True,
                )
                st.caption(f"Total: {len(rows)} certificates")
            else:
                st.info("No certificates.")
        with cert_sub[1]:
            _show(parser.get_ssl_tls_profiles(), "No SSL/TLS profiles.", key="ssl_tls")
        with cert_sub[2]:
            _show(
                parser.get_certificate_profiles(), "No cert profiles.", key="cert_prof"
            )
        with cert_sub[3]:
            _show(parser.get_ocsp_responders(), "No OCSP responders.", key="ocsp")
        with cert_sub[4]:
            _show(parser.get_scep_profiles(), "No SCEP profiles.", key="scep")
        with cert_sub[5]:
            _show(
                parser.get_ssl_decrypt_exclusions(),
                "No SSL decryption exclusions.",
                key="ssl_excl",
            )
        with cert_sub[6]:
            _show(
                parser.get_ssh_service_profiles(),
                "No SSH service profiles.",
                key="ssh_sp",
            )

    # ── 14. LOG SETTINGS ──────────────────────────────────────
    with tabs[13]:
        st.markdown("#### 📋 Log Settings")
        ls = parser.get_log_settings_tables()
        alarm = parser.get_alarm_settings()
        log_sub = st.tabs(
            [
                "System",
                "Configuration",
                "User-ID",
                "HIP Match",
                "GlobalProtect",
                "IP-Tag",
                "Alarm Settings",
            ]
        )
        for i, (lt, label) in enumerate(
            [
                ("system", "System"),
                ("configuration", "Configuration"),
                ("user-id", "User-ID"),
                ("hip-match", "HIP Match"),
                ("globalprotect", "GlobalProtect"),
                ("iptag", "IP-Tag"),
            ]
        ):
            with log_sub[i]:
                rows = ls.get(lt, [])
                if rows:
                    st.dataframe(
                        pd.DataFrame(rows), use_container_width=True, hide_index=True
                    )
                    st.caption(f"Total: {len(rows)} entries")
                else:
                    st.info(f"No {label} log settings.")
        with log_sub[6]:
            if alarm:
                c1, c2 = st.columns(2)
                items = list(alarm.items())
                mid = len(items) // 2
                with c1:
                    _infobox("Alarm Configuration", dict(items[:mid]))
                with c2:
                    _infobox("Thresholds", dict(items[mid:]))
            else:
                st.info("No alarm settings.")

    # ── 15. SERVER PROFILES ───────────────────────────────────
    with tabs[14]:
        st.markdown("#### 🖥️ Server Profiles")
        sp_sub = st.tabs(
            [
                "RADIUS",
                "LDAP",
                "Syslog",
                "Email",
                "SNMP",
                "HTTP",
                "NetFlow",
                "SCP",
                "TACACS+",
                "Kerberos",
                "SAML IdP",
                "MFA",
            ]
        )
        with sp_sub[0]:
            _show(parser.get_radius_profiles(), "No RADIUS.", key="sp_rad")
        with sp_sub[1]:
            _show(parser.get_ldap_profiles(), "No LDAP.", key="sp_ldap")
        with sp_sub[2]:
            _show(parser.get_syslog_profiles(), "No Syslog.", key="sp_syslog")
        with sp_sub[3]:
            _show(parser.get_email_profiles(), "No Email.", key="sp_email")
        with sp_sub[4]:
            _show(parser.get_snmp_profiles(), "No SNMP.", key="sp_snmp")
        with sp_sub[5]:
            _show(parser.get_http_profiles(), "No HTTP.", key="sp_http")
        with sp_sub[6]:
            _show(parser.get_netflow_profiles(), "No NetFlow.", key="sp_nf")
        with sp_sub[7]:
            _show(parser.get_scp_profiles(), "No SCP.", key="sp_scp")
        with sp_sub[8]:
            _show(parser.get_tacacs_profiles(), "No TACACS+.", key="sp_tac")
        with sp_sub[9]:
            _show(parser.get_kerberos_profiles(), "No Kerberos.", key="sp_krb")
        with sp_sub[10]:
            _show(parser.get_saml_idp_profiles(), "No SAML IdP.", key="sp_saml")
        with sp_sub[11]:
            _show(parser.get_mfa_profiles(), "No MFA.", key="sp_mfa")

    # ── 16. LOCAL USER DATABASE ───────────────────────────────
    with tabs[15]:
        st.markdown("#### 👥 Local User Database")
        lu_sub = st.tabs(["Users", "User Groups"])
        with lu_sub[0]:
            rows = parser.get_local_users()
            if rows:
                df = pd.DataFrame(rows)
                search = st.text_input("Search user", key="ludb_search")
                if search:
                    df = df[df["Name"].str.contains(search, case=False, na=False)]
                st.dataframe(df, use_container_width=True, hide_index=True)
                st.caption(f"Showing {len(df)} of {len(rows)} users")
            else:
                st.info("No local users.")
        with lu_sub[1]:
            rows = parser.get_local_user_groups()
            if rows:
                for grp in rows:
                    with st.expander(f"**{grp['Name']}** ({grp['Count']} members)"):
                        st.markdown(grp["Members"])
                st.caption(f"Total: {len(rows)} groups")
            else:
                st.info("No user groups.")

    # ── 17. SCHEDULED LOG EXPORT ──────────────────────────────
    with tabs[16]:
        st.markdown("#### 📤 Scheduled Log Export")
        _show(parser.get_scheduled_log_export(), "No scheduled log exports.", key="sle")


# Palo Alto Device views – full rebuild with all enhancements.
