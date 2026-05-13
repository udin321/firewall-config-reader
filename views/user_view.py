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


def render_user_auth(parser):
    st.subheader("User & Authentication")

    tab_users, tab_groups, tab_guest, tab_ldap, tab_radius, tab_fsso, tab_token, tab_auth = st.tabs([
        "User Definition", "User Groups", "Guest Management",
        "LDAP Servers", "RADIUS Servers", "Single Sign-On",
        "FortiToken", "Auth Settings"
    ])

    with tab_users:
        st.markdown("#### User Definitions")
        rows = parser.parse_user_local()
        if rows:
            df = pd.DataFrame(rows)
            def highlight_status(row):
                if str(row.get("Status","")).lower() == "disable":
                    return ["background-color:#fff3cd"] * len(row)
                return [""] * len(row)
            st.dataframe(df.style.apply(highlight_status, axis=1), use_container_width=True, hide_index=True)
        else:
            st.info("No local users configured.")

    with tab_groups:
        st.markdown("#### User Groups")
        _show_table(parser.parse_user_groups(), "No user groups configured.")

    with tab_guest:
        st.markdown("#### Guest Management")
        _show_table(parser.parse_guest_users(), "No guest users configured.")

    with tab_ldap:
        st.markdown("#### LDAP Servers")
        _show_table(parser.parse_ldap(), "No LDAP servers configured.")

    with tab_radius:
        st.markdown("#### RADIUS Servers")
        _show_table(parser.parse_radius(), "No RADIUS servers configured.")

    with tab_fsso:
        st.markdown("#### Single Sign-On (FSSO)")
        _show_table(parser.parse_fsso(), "No FSSO agents configured.")

    with tab_token:
        st.markdown("#### FortiToken")
        rows = parser.parse_fortitoken()
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            st.caption(f"Total tokens: {len(rows)}")
        else:
            st.info("No FortiTokens configured.")

    with tab_auth:
        st.markdown("#### Authentication Settings")
        auth = parser.parse_auth_settings()
        if auth:
            c1, c2 = st.columns(2)
            c1.metric("Auth Certificate", auth.get("auth_cert", "-"))
            c2.metric("Auth Timeout",     f"{auth.get('auth_timeout', '5')} minutes")

            st.divider()
            st.markdown("#### User Authentication Options")
            st.markdown("**Protocol Support**")

            # auth_type is a space-separated list like "http https" or "http https telnet ssh"
            auth_type_raw = auth.get("auth_type", "http https")
            active_protos = [p.strip().upper() for p in auth_type_raw.split()]

            # Show all 4 protocols as enabled/disabled badges
            all_protos = ["HTTP", "HTTPS", "TELNET", "SSH"]
            cols = st.columns(len(all_protos))
            for col, proto in zip(cols, all_protos):
                enabled = proto in active_protos
                bg  = "#2ecc71" if enabled else "#e74c3c"
                col.markdown(
                    f'<div style="background:{bg};color:white;border-radius:10px;'
                    f'padding:10px;text-align:center;font-weight:bold;font-size:14px">'
                    f'{proto}<br><span style="font-size:11px">{"ON" if enabled else "OFF"}</span></div>',
                    unsafe_allow_html=True
                )

            st.divider()
            st.markdown("**HTTP Redirect**")
            _toggle("HTTP Redirect to Auth Portal", auth.get("http_redirect", "disable"))
        else:
            st.info("No authentication settings found.")
