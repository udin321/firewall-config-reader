"""views/user_view.py — FortiGate User & Auth tab with search + CSV on every table."""

import streamlit as st
import pandas as pd
from views.table_utils import st_table


def _toggle(label, value):
    on = str(value).lower() in ["enable", "on", "1", "true"]
    col = "#2ecc71" if on else "#ccc"
    bg = "#e8f8f0" if on else "#f5f5f5"
    text = "ON" if on else "OFF"
    st.markdown(
        f'<div style="display:flex;align-items:center;justify-content:space-between;'
        f'background:{bg};border-radius:8px;padding:8px 14px;margin:4px 0">'
        f'<span style="font-size:13px">{label}</span>'
        f'<span style="background:{col};color:white;padding:2px 12px;'
        f'border-radius:12px;font-size:12px;font-weight:bold">{text}</span></div>',
        unsafe_allow_html=True,
    )


def render_user_auth(parser):
    st.subheader("User & Authentication")

    tabs = st.tabs(
        [
            "User Definition",
            "User Groups",
            "Guest Management",
            "LDAP Servers",
            "RADIUS Servers",
            "Single Sign-On",
            "FortiToken",
            "Auth Settings",
        ]
    )

    with tabs[0]:
        st.markdown("#### User Definitions")
        rows = parser.parse_user_local()
        if rows:

            def _hl(row):
                if str(row.get("Status", "")).lower() == "disable":
                    return ["background-color:#fff3cd"] * len(row)
                return [""] * len(row)

            st_table(rows, key="fg_users", style_fn=_hl, export_filename="fg_users.csv")
        else:
            st.info("No local users configured.")

    with tabs[1]:
        st.markdown("#### User Groups")
        rows = parser.parse_user_groups()
        if rows:
            st_table(rows, key="fg_user_groups", export_filename="fg_user_groups.csv")
        else:
            st.info("No user groups configured.")

    with tabs[2]:
        st.markdown("#### Guest Management")
        rows = parser.parse_guest_users()
        if rows:
            st_table(rows, key="fg_guest_users", export_filename="fg_guest_users.csv")
        else:
            st.info("No guest users configured.")

    with tabs[3]:
        st.markdown("#### LDAP Servers")
        rows = parser.parse_ldap()
        if rows:
            st_table(rows, key="fg_ldap", export_filename="fg_ldap_servers.csv")
        else:
            st.info("No LDAP servers configured.")

    with tabs[4]:
        st.markdown("#### RADIUS Servers")
        rows = parser.parse_radius()
        if rows:
            st_table(rows, key="fg_radius", export_filename="fg_radius_servers.csv")
        else:
            st.info("No RADIUS servers configured.")

    with tabs[5]:
        st.markdown("#### Single Sign-On (FSSO)")
        rows = parser.parse_fsso()
        if rows:
            st_table(rows, key="fg_fsso", export_filename="fg_fsso.csv")
        else:
            st.info("No FSSO agents configured.")

    with tabs[6]:
        st.markdown("#### FortiToken")
        rows = parser.parse_fortitoken()
        if rows:
            st_table(
                rows,
                key="fg_fortitoken",
                caption=f"Total: {len(rows)} tokens",
                export_filename="fg_fortitokens.csv",
            )
        else:
            st.info("No FortiTokens configured.")

    with tabs[7]:
        st.markdown("#### Authentication Settings")
        auth = parser.parse_auth_settings()
        if auth:
            c1, c2 = st.columns(2)
            c1.metric("Auth Certificate", auth.get("auth_cert", "-"))
            c2.metric("Auth Timeout", f"{auth.get('auth_timeout','5')} minutes")
            st.divider()
            st.markdown("**Protocol Support**")
            active = [
                p.strip().upper() for p in auth.get("auth_type", "http https").split()
            ]
            for col, proto in zip(st.columns(4), ["HTTP", "HTTPS", "TELNET", "SSH"]):
                ok = proto in active
                col.markdown(
                    f'<div style="background:{"#2ecc71" if ok else "#e74c3c"};'
                    f"color:white;border-radius:10px;padding:10px;text-align:center;"
                    f'font-weight:bold">{proto}<br>'
                    f'<span style="font-size:11px">{"ON" if ok else "OFF"}</span></div>',
                    unsafe_allow_html=True,
                )
            st.divider()
            _toggle(
                "HTTP Redirect to Auth Portal", auth.get("http_redirect", "disable")
            )
        else:
            st.info("No authentication settings found.")
