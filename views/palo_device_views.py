"""
views/palo_device_views.py
Palo Alto — Device tab.

Every table uses st_table() → free-text search + column filter + CSV export.
"""

from __future__ import annotations
import streamlit as st
from views.table_utils import st_table

# ── small helpers ──────────────────────────────────────────────────────────────


def _kv(label: str, value: str):
    st.markdown(
        f'<div style="display:flex;justify-content:space-between;align-items:center;'
        f'padding:6px 4px;border-bottom:1px solid #30363d22;font-size:13px">'
        f'<span style="color:#8b949e">{label}</span>'
        f'<b style="color:#e6edf3">{value}</b></div>',
        unsafe_allow_html=True,
    )


def _toggle(label: str, val: str):
    on = str(val).lower() in ("yes", "enable", "true", "1")
    c, t = ("#3fb950", "✅ Enabled") if on else ("#f85149", "❌ Disabled")
    st.markdown(
        f'<div style="display:flex;justify-content:space-between;padding:6px 4px;'
        f'border-bottom:1px solid #30363d22;font-size:13px">'
        f'<span style="color:#8b949e">{label}</span>'
        f'<span style="color:{c};font-weight:700">{t}</span></div>',
        unsafe_allow_html=True,
    )


def _dict_table(d: dict, key: str, fname: str):
    """Render a dict as a 2-column searchable table."""
    if not d:
        st.info("No data.")
        return
    rows = [{"Setting": k, "Value": v} for k, v in d.items()]
    st_table(rows, key=key, export_filename=fname)


def _section(icon: str, title: str):
    st.markdown(
        f'<div style="display:flex;align-items:center;gap:8px;margin:18px 0 8px;'
        f'border-left:3px solid #3a7bd5;padding-left:10px">'
        f'<span style="font-size:15px">{icon}</span>'
        f'<span style="font-size:15px;font-weight:700;color:#e6edf3">{title}</span>'
        f"</div>",
        unsafe_allow_html=True,
    )


# ── HA rendering ───────────────────────────────────────────────────────────────


def _render_ha(parser):
    gen = parser.get_ha_general()

    enabled_raw = str(gen.get("enabled", "no")).lower()
    if enabled_raw not in ("yes", "true", "1", "enable"):
        st.info("ℹ️ High Availability is **disabled** on this device.")
        return

    mode = gen.get("mode", "active-passive").upper()
    st.success(f"✅ HA Mode: **{mode}**  |  Group ID: **{gen.get('group_id','-')}**")

    # General / Election Settings
    with st.expander("⚙️ General / Election Settings", expanded=True):
        # device-priority defaults to 100 in PAN-OS when not explicitly set
        priority = gen.get("priority", "-")
        if priority in ("-", "", None):
            priority = "100 (PAN-OS default)"

        c1, c2 = st.columns(2)
        with c1:
            _kv("Device Priority", priority)
            _kv("Preemptive", str(gen.get("preemptive", "no")).upper())
        with c2:
            _kv("Config Sync", str(gen.get("config_sync", "no")).upper())
            _kv("Peer HA1 IP", gen.get("peer_ha1_ip", "-"))
        if gen.get("description"):
            _kv("Description", gen["description"])

    # Active / Passive Settings
    ap = {}
    try:
        ap = parser.get_ha_active_passive()
    except Exception:
        pass

    with st.expander("🔗 Active / Passive Settings", expanded=True):
        if ap:
            pls = ap.get("Passive Link State", "shutdown")
            mfhd = ap.get("Monitor Fail Hold Down (min)", "1")
        else:
            # PAN-OS defaults when block is absent
            pls = "shutdown"
            mfhd = "1"

        pls_color = "#d29922" if pls.lower() == "auto" else "#3fb950"
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(
                f'<div style="padding:6px 4px;font-size:13px">'
                f"Passive Link State: "
                f'<span style="color:{pls_color};font-weight:700">{pls.upper()}</span>'
                f'<span style="font-size:11px;color:#8b949e"> (default: Shutdown)</span>'
                f"</div>",
                unsafe_allow_html=True,
            )
        with c2:
            _kv("Monitor Fail Hold Down (min)", mfhd + " (default: 1)")

    # HA Interfaces
    try:
        ifaces = parser.get_ha_interfaces()
    except Exception:
        ifaces = {}
    if ifaces:
        with st.expander("🔌 HA Interfaces"):
            for name, info in ifaces.items():
                st.markdown(f"**{name.upper()}**")
                c1, c2, c3 = st.columns(3)
                c1.metric("Port", info.get("port", "-"))
                c2.metric("IP Address", info.get("ip_address", "-"))
                c3.metric("Encryption", info.get("encryption", "no").upper())

    # Link & Path Monitoring
    try:
        lpm = parser.get_ha_link_path_monitoring()
    except Exception:
        lpm = {}

    with st.expander("📡 Link & Path Monitoring", expanded=True):
        # PAN-OS enables both by default — show "yes" when config block is absent
        link_en = lpm.get("link_enabled", "yes")
        path_en = lpm.get("path_enabled", "yes")
        note = lpm.get("_defaults_note", "")

        c1, c2 = st.columns(2)
        with c1:
            _toggle("Link Monitoring", link_en)
            _kv("Link Fail Condition", lpm.get("link_fail_cond", "any").upper())
            lgroups = lpm.get("link_groups", [])
            if lgroups:
                st_table(
                    lgroups,
                    key="pa_ha_link_groups",
                    export_filename="pa_ha_link_groups.csv",
                )
            else:
                st.caption("No link monitoring groups configured.")
        with c2:
            _toggle("Path Monitoring", path_en)
            _kv("Path Fail Condition", lpm.get("path_fail_cond", "any").upper())
            pgroups = lpm.get("path_groups", [])
            if pgroups:
                st_table(
                    pgroups,
                    key="pa_ha_path_groups",
                    export_filename="pa_ha_path_groups.csv",
                )
            else:
                st.caption("No path monitoring groups configured.")
        if note:
            st.caption(f"ℹ️ {note}")


# ── Main render ────────────────────────────────────────────────────────────────


def render_pa_device(parser):
    st.subheader("⚙️ Device")

    tabs = st.tabs(
        [
            "Setup",
            "High Availability",
            "Administrators",
            "Auth Profiles",
            "Certificates",
            "Server Profiles",
            "Log Settings",
            "Session",
            "User-ID",
        ]
    )

    # ── Setup ──────────────────────────────────────────────────────────────
    with tabs[0]:
        st.markdown("#### General Settings")
        _dict_table(
            parser.get_general_settings(),
            key="pa_gen_settings",
            fname="pa_general_settings.csv",
        )

        st.markdown("#### Management Interface")
        _dict_table(
            parser.get_mgmt_interface(),
            key="pa_mgmt_iface",
            fname="pa_mgmt_interface.csv",
        )

        st.markdown("#### Management Services")
        svc = parser.get_mgmt_services()
        if svc:
            _toggle(
                "Telnet", "no" if svc.get("disable_telnet", "no") == "yes" else "yes"
            )
            _toggle("HTTP", "no" if svc.get("disable_http", "no") == "yes" else "yes")
            _toggle("HTTPS", "no" if svc.get("disable_https", "no") == "yes" else "yes")
            _toggle("SSH", "no" if svc.get("disable_ssh", "no") == "yes" else "yes")

        st.markdown("#### Services (DNS / NTP)")
        _dict_table(
            parser.get_services_config(),
            key="pa_svc_cfg",
            fname="pa_services_config.csv",
        )

        st.markdown("#### Service Routes")
        rows = parser.get_service_routes()
        if rows:
            st_table(rows, key="pa_svc_routes", export_filename="pa_service_routes.csv")
        else:
            st.info("No service routes configured.")

        st.markdown("#### Panorama")
        _dict_table(
            parser.get_panorama_settings(),
            key="pa_panorama",
            fname="pa_panorama_settings.csv",
        )

        st.markdown("#### Logging Settings")
        _dict_table(
            parser.get_logging_settings(),
            key="pa_logging",
            fname="pa_logging_settings.csv",
        )

        st.markdown("#### Authentication Settings")
        _dict_table(
            parser.get_auth_settings(),
            key="pa_auth_settings",
            fname="pa_auth_settings.csv",
        )

        st.markdown("#### Password Complexity")
        _dict_table(
            parser.get_password_complexity(),
            key="pa_pwd_complex",
            fname="pa_password_complexity.csv",
        )

    # ── High Availability ──────────────────────────────────────────────────
    with tabs[1]:
        _render_ha(parser)

    # ── Administrators ─────────────────────────────────────────────────────
    with tabs[2]:
        st.markdown("#### Administrators")
        rows = parser.get_admins()
        if rows:
            st_table(rows, key="pa_admins", export_filename="pa_admins.csv")
        else:
            st.info("No administrator accounts found.")

        st.markdown("#### Password Profiles")
        rows = parser.get_password_profiles()
        if rows:
            st_table(
                rows, key="pa_pwd_profiles", export_filename="pa_password_profiles.csv"
            )
        else:
            st.info("No password profiles found.")

        st.markdown("#### Admin Roles")
        rows = parser.get_admin_roles()
        if rows:
            st_table(rows, key="pa_admin_roles", export_filename="pa_admin_roles.csv")
        else:
            st.info("No admin roles found.")

        st.markdown("#### Local Users")
        rows = parser.get_local_users()
        if rows:
            st_table(rows, key="pa_local_users", export_filename="pa_local_users.csv")
        else:
            st.info("No local users found.")

        st.markdown("#### Local User Groups")
        rows = parser.get_local_user_groups()
        if rows:
            st_table(
                rows, key="pa_local_groups", export_filename="pa_local_user_groups.csv"
            )
        else:
            st.info("No local user groups found.")

    # ── Auth Profiles ──────────────────────────────────────────────────────
    with tabs[3]:
        st.markdown("#### Authentication Profiles")
        rows = parser.get_auth_profiles()
        if rows:
            st_table(rows, key="pa_auth_profs", export_filename="pa_auth_profiles.csv")
        else:
            st.info("No authentication profiles found.")

        st.markdown("#### Authentication Sequences")
        rows = parser.get_auth_sequences()
        if rows:
            st_table(rows, key="pa_auth_seqs", export_filename="pa_auth_sequences.csv")
        else:
            st.info("No authentication sequences found.")

        st.markdown("#### RADIUS Profiles")
        rows = parser.get_radius_profiles()
        if rows:
            st_table(rows, key="pa_radius", export_filename="pa_radius_profiles.csv")
        else:
            st.info("No RADIUS profiles found.")

        st.markdown("#### LDAP Profiles")
        rows = parser.get_ldap_profiles()
        if rows:
            st_table(rows, key="pa_ldap", export_filename="pa_ldap_profiles.csv")
        else:
            st.info("No LDAP profiles found.")

        st.markdown("#### TACACS+ Profiles")
        rows = parser.get_tacacs_profiles()
        if rows:
            st_table(rows, key="pa_tacacs", export_filename="pa_tacacs_profiles.csv")
        else:
            st.info("No TACACS+ profiles found.")

        st.markdown("#### Kerberos Profiles")
        rows = parser.get_kerberos_profiles()
        if rows:
            st_table(
                rows, key="pa_kerberos", export_filename="pa_kerberos_profiles.csv"
            )
        else:
            st.info("No Kerberos profiles found.")

        st.markdown("#### SAML IdP Profiles")
        rows = parser.get_saml_idp_profiles()
        if rows:
            st_table(rows, key="pa_saml", export_filename="pa_saml_profiles.csv")
        else:
            st.info("No SAML IdP profiles found.")

        st.markdown("#### MFA Profiles")
        rows = parser.get_mfa_profiles()
        if rows:
            st_table(rows, key="pa_mfa", export_filename="pa_mfa_profiles.csv")
        else:
            st.info("No MFA profiles found.")

    # ── Certificates ───────────────────────────────────────────────────────
    with tabs[4]:
        st.markdown("#### Certificates")
        rows = parser.get_certificates()
        if rows:
            st_table(rows, key="pa_certs", export_filename="pa_certificates.csv")
        else:
            st.info("No certificates found.")

        st.markdown("#### SSL/TLS Service Profiles")
        rows = parser.get_ssl_tls_profiles()
        if rows:
            st_table(rows, key="pa_ssl_tls", export_filename="pa_ssl_tls_profiles.csv")
        else:
            st.info("No SSL/TLS profiles found.")

        st.markdown("#### Certificate Profiles")
        rows = parser.get_certificate_profiles()
        if rows:
            st_table(rows, key="pa_cert_profs", export_filename="pa_cert_profiles.csv")
        else:
            st.info("No certificate profiles found.")

        st.markdown("#### OCSP Responders")
        rows = parser.get_ocsp_responders()
        if rows:
            st_table(rows, key="pa_ocsp", export_filename="pa_ocsp_responders.csv")
        else:
            st.info("No OCSP responders found.")

        st.markdown("#### SCEP Profiles")
        rows = parser.get_scep_profiles()
        if rows:
            st_table(rows, key="pa_scep", export_filename="pa_scep_profiles.csv")
        else:
            st.info("No SCEP profiles found.")

        st.markdown("#### SSL Decrypt Exclusions")
        rows = parser.get_ssl_decrypt_exclusions()
        if rows:
            st_table(
                rows, key="pa_ssl_excl", export_filename="pa_ssl_decrypt_exclusions.csv"
            )
        else:
            st.info("No SSL decrypt exclusions found.")

    # ── Server Profiles ────────────────────────────────────────────────────
    with tabs[5]:
        st.markdown("#### Syslog Profiles")
        rows = parser.get_syslog_profiles()
        if rows:
            st_table(rows, key="pa_syslog", export_filename="pa_syslog_profiles.csv")
        else:
            st.info("No syslog profiles found.")

        st.markdown("#### Email Profiles")
        rows = parser.get_email_profiles()
        if rows:
            st_table(rows, key="pa_email", export_filename="pa_email_profiles.csv")
        else:
            st.info("No email profiles found.")

        st.markdown("#### SNMP Profiles")
        rows = parser.get_snmp_profiles()
        if rows:
            st_table(rows, key="pa_snmp", export_filename="pa_snmp_profiles.csv")
        else:
            st.info("No SNMP profiles found.")

        st.markdown("#### HTTP Profiles")
        rows = parser.get_http_profiles()
        if rows:
            st_table(rows, key="pa_http", export_filename="pa_http_profiles.csv")
        else:
            st.info("No HTTP profiles found.")

        st.markdown("#### Netflow Profiles")
        rows = parser.get_netflow_profiles()
        if rows:
            st_table(rows, key="pa_netflow", export_filename="pa_netflow_profiles.csv")
        else:
            st.info("No Netflow profiles found.")

        st.markdown("#### SCP Profiles")
        rows = parser.get_scp_profiles()
        if rows:
            st_table(rows, key="pa_scp", export_filename="pa_scp_profiles.csv")
        else:
            st.info("No SCP profiles found.")

        st.markdown("#### SSH Service Profiles")
        rows = parser.get_ssh_service_profiles()
        if rows:
            st_table(
                rows, key="pa_ssh_profs", export_filename="pa_ssh_service_profiles.csv"
            )
        else:
            st.info("No SSH service profiles found.")

    # ── Log Settings ───────────────────────────────────────────────────────
    with tabs[6]:
        log_tabs = parser.get_log_settings_tables()

        st.markdown("#### Syslog (Direct)")
        rows = parser.get_syslog_direct()
        if rows:
            st_table(
                rows, key="pa_syslog_direct", export_filename="pa_syslog_direct.csv"
            )
        else:
            st.info("No direct syslog config found.")

        st.markdown("#### Scheduled Log Export")
        rows = parser.get_scheduled_log_export()
        if rows:
            st_table(
                rows, key="pa_sched_log", export_filename="pa_scheduled_log_export.csv"
            )
        else:
            st.info("No scheduled log exports found.")

        if log_tabs:
            for tname, trows in log_tabs.items():
                st.markdown(f"#### {tname}")
                if isinstance(trows, list) and trows:
                    safe_key = tname.lower().replace(" ", "_").replace("/", "_")
                    st_table(
                        trows,
                        key=f"pa_log_{safe_key}",
                        export_filename=f"pa_log_{safe_key}.csv",
                    )
                elif isinstance(trows, dict):
                    st_table(
                        [{"Setting": k, "Value": v} for k, v in trows.items()],
                        key=f"pa_log_{tname[:20]}",
                        export_filename=f"pa_log_{tname[:20]}.csv",
                    )

        st.markdown("#### Alarm Settings")
        alarm = parser.get_alarm_settings()
        if alarm:
            _dict_table(alarm, key="pa_alarms", fname="pa_alarm_settings.csv")

    # ── Session ────────────────────────────────────────────────────────────
    with tabs[7]:
        st.markdown("#### Session Settings")
        _dict_table(
            parser.get_session_settings(),
            key="pa_sess_settings",
            fname="pa_session_settings.csv",
        )

        st.markdown("#### Session Timeouts")
        _dict_table(
            parser.get_session_timeouts(),
            key="pa_sess_timeouts",
            fname="pa_session_timeouts.csv",
        )

        st.markdown("#### TCP Settings")
        _dict_table(
            parser.get_tcp_settings(),
            key="pa_tcp_settings",
            fname="pa_tcp_settings.csv",
        )

        st.markdown("#### VPN Session Settings")
        _dict_table(
            parser.get_vpn_session_settings(),
            key="pa_vpn_sess",
            fname="pa_vpn_session_settings.csv",
        )

        st.markdown("#### DLP Settings")
        dlp = parser.get_dlp_settings()
        if dlp:
            for section, data in dlp.items():
                if isinstance(data, dict) and data:
                    st.markdown(f"**{section.replace('_',' ').title()}**")
                    _dict_table(
                        data, key=f"pa_dlp_{section}", fname=f"pa_dlp_{section}.csv"
                    )

    # ── User-ID ────────────────────────────────────────────────────────────
    with tabs[8]:
        uid = parser.get_user_id_info()
        if not uid:
            st.info("No User-ID configuration found.")
        else:
            st.markdown("#### User-ID Settings")
            _dict_table(
                uid.get("settings", {}),
                key="pa_uid_settings",
                fname="pa_userid_settings.csv",
            )

            st.markdown("#### User-ID Agents")
            rows = uid.get("agents", [])
            if rows:
                st_table(
                    rows, key="pa_uid_agents", export_filename="pa_userid_agents.csv"
                )
            else:
                st.info("No User-ID agents configured.")

            st.markdown("#### User-ID Include/Exclude Networks")
            rows = uid.get("networks", [])
            if rows:
                st_table(
                    rows,
                    key="pa_uid_networks",
                    export_filename="pa_userid_networks.csv",
                )

            st.markdown("#### Syslog Senders")
            rows = uid.get("syslog_senders", [])
            if rows:
                st_table(
                    rows,
                    key="pa_uid_syslog",
                    export_filename="pa_userid_syslog_senders.csv",
                )
            else:
                st.info("No syslog senders configured.")
