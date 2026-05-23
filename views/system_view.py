"""views/system_view.py — FortiGate System tab. Administrators section uses st_table."""

import streamlit as st
import pandas as pd
from views.table_utils import st_table


def _toggle(label, value):
    on = str(value).lower() in ["enable", "on", "1", "true"]
    color = "#2ecc71" if on else "#ccc"
    bg = "#e8f8f0" if on else "#f5f5f5"
    text = "ON" if on else "OFF"
    st.markdown(
        f'<div style="display:flex;align-items:center;justify-content:space-between;'
        f'background:{bg};border-radius:8px;padding:8px 14px;margin:4px 0;">'
        f'<span style="font-size:13px">{label}</span>'
        f'<span style="background:{color};color:white;padding:2px 12px;'
        f'border-radius:12px;font-size:12px;font-weight:bold">{text}</span></div>',
        unsafe_allow_html=True,
    )


def _scope_selector(current_scope):
    scopes = [
        ("off", "Off"),
        ("admin", "Admin"),
        ("ipsec", "IPSec"),
        ("admin-ipsec", "Both"),
    ]
    cols = st.columns(len(scopes))
    for col, (val, label) in zip(cols, scopes):
        is_sel = current_scope.lower() == val
        bg = "#2c3e50" if is_sel else "#ecf0f1"
        fg = "white" if is_sel else "#666"
        col.markdown(
            f'<div style="background:{bg};color:{fg};border-radius:8px;padding:10px;'
            f'text-align:center;font-weight:{"bold" if is_sel else "normal"};font-size:13px">'
            f'{label}{"  ✓" if is_sel else ""}</div>',
            unsafe_allow_html=True,
        )


def render_system(parser):
    st.subheader("System")

    tab_admin, tab_profile, tab_settings, tab_ha, tab_snmp = st.tabs(
        [
            "Administrators",
            "Admin Profiles",
            "Settings",
            "HA",
            "SNMP",
        ]
    )

    # ── Administrators — uses st_table ────────────────────────
    with tab_admin:
        st.markdown("#### Administrators")
        rows = parser.parse_admins()
        if not rows:
            st.info("No administrators configured.")
        else:
            rows = sorted(
                rows,
                key=lambda x: (0 if x["Profile"] == "super_admin" else 1, x["Name"]),
            )

            def _hl_admin(row):
                if row.get("Profile") == "super_admin":
                    return ["background-color:#fef9e7"] * len(row)
                return [""] * len(row)

            st_table(
                rows,
                key="fg_admins",
                style_fn=_hl_admin,
                export_filename="fg_administrators.csv",
                caption="🌟 Yellow = super_admin",
            )

    # ── Admin Profiles ────────────────────────────────────────
    with tab_profile:
        st.markdown("#### Admin Profiles")
        profiles = parser.parse_accprofiles()
        if not profiles:
            st.info("No admin profiles configured.")
        else:
            perm_cols = [
                "Security Fabric",
                "FortiView",
                "User & Device",
                "Firewall",
                "Log & Report",
                "Network",
                "System",
                "Security Profile",
                "VPN",
                "WiFi & Switch",
            ]
            COLOURS = {"Read/Write": "#27ae60", "Read": "#2980b9", "None": "#95a5a6"}
            for prof in profiles:
                with st.expander(f"**{prof['name']}**", expanded=False):
                    if prof.get("comments"):
                        st.caption(prof["comments"])
                    cols = st.columns(len(perm_cols))
                    for col, perm in zip(cols, perm_cols):
                        val = prof.get(perm, "None")
                        bg = COLOURS.get(val, "#95a5a6")
                        col.markdown(
                            f'<div style="text-align:center;padding:6px 2px">'
                            f'<div style="font-size:10px;color:#666;margin-bottom:4px">{perm}</div>'
                            f'<span style="background:{bg};color:white;padding:3px 8px;'
                            f'border-radius:8px;font-size:11px;font-weight:bold">{val}</span></div>',
                            unsafe_allow_html=True,
                        )

    # ── Settings ──────────────────────────────────────────────
    with tab_settings:
        s = parser.parse_system_settings()
        if not s:
            st.info("No system settings found.")
        else:
            TIMEZONES = {
                "57": "Asia/Kuala_Lumpur (UTC+8)",
                "0": "UTC",
                "4": "America/New_York (UTC-5)",
                "12": "America/Los_Angeles (UTC-8)",
                "26": "Europe/London (UTC+0)",
                "28": "Europe/Paris (UTC+1)",
                "55": "Asia/Singapore (UTC+8)",
                "29": "Asia/Tokyo (UTC+9)",
            }
            tz_raw = s.get("timezone", "")
            tz_disp = TIMEZONES.get(tz_raw, f"TZ {tz_raw}")
            c1, c2, c3 = st.columns(3)
            c1.metric("Hostname", s.get("hostname", "-"))
            c2.metric("Time Zone", tz_disp)
            c3.metric("VDOM Mode", s.get("vdom_status", "disable"))
            st.divider()
            _toggle("FortiGuard Updates", s.get("fgd_alert_subscription", "disable"))
            _toggle(
                "Revision Backup on Upgrade",
                s.get("revision_backup_on_upgrade", "disable"),
            )
            if s.get("admin_lockout_threshold"):
                st.metric("Admin Lockout Threshold", s["admin_lockout_threshold"])

    # ── HA ────────────────────────────────────────────────────
    with tab_ha:
        ha = parser.get_ha_config()

        if not ha.get("enabled"):
            st.info("ℹ️ HA is not configured (Standalone mode).")

        else:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Mode", ha.get("mode", "-"))
            c2.metric("Group Name", ha.get("group_name", "-"))
            c3.metric("Priority", ha.get("priority", "-"))
            c4.metric(
                "Session Pickup",
                "🟢 ON" if ha.get("session_pickup") == "enable" else "⚪ OFF",
            )

            st.divider()

            _toggle("Override", ha.get("override", "disable"))

            st.subheader("Heartbeat Interfaces")

            if ha.get("heartbeat_interfaces"):
                st.write(", ".join(ha["heartbeat_interfaces"]))
            else:
                st.write("")

            st.subheader("Monitor Interfaces")

            if ha.get("monitor_interfaces"):
                st.write(", ".join(ha["monitor_interfaces"]))
            else:
                st.write("")

            st.divider()

            st.subheader("Management Interface Reservation")

            _toggle("HA Management", ha.get("ha_mgmt_status", "disable"))

            if ha.get("ha_mgmt_status") == "enable":

                for m in ha.get("ha_mgmt_interfaces", []):

                    st.markdown(f"""
    **Interface:** {m['interface']}

    **Gateway:** {m['gateway']}

    **Destination Subnet:** {m['destination']}
    """)
                    st.divider()

    # ── SNMP ──────────────────────────────────────────────────
    with tab_snmp:
        st.markdown("#### SNMP")
        try:
            snmp = parser.parse_snmp()
        except AttributeError:
            snmp = {}
        if not snmp:
            st.info("No SNMP configuration found.")
        else:
            c1, c2 = st.columns(2)
            c1.metric("Sys Contact", snmp.get("contact", "-"))
            c2.metric("Sys Location", snmp.get("location", "-"))
            communities = snmp.get("communities", [])
            if communities:
                st.markdown("**Communities**")
                st_table(
                    communities,
                    key="fg_snmp_communities",
                    export_filename="fg_snmp_communities.csv",
                )
            users = snmp.get("users", [])
            if users:
                st.markdown("**SNMPv3 Users**")
                st_table(
                    users, key="fg_snmpv3_users", export_filename="fg_snmpv3_users.csv"
                )
