"""views/wifi_view.py — FortiGate WiFi & Switch tab. Every table: search + CSV."""

import streamlit as st
import pandas as pd
from views.table_utils import st_table


def _toggle_badge(label, value):
    on = str(value).lower() in ["enable", "on", "1", "true"]
    color = "#2ecc71" if on else "#e74c3c"
    text = "ON" if on else "OFF"
    st.markdown(
        f'<span style="background:{color};color:white;padding:2px 10px;'
        f'border-radius:12px;font-size:11px;font-weight:bold;margin-right:6px">{text}</span>'
        f'<span style="font-size:13px">{label}</span>',
        unsafe_allow_html=True,
    )


def render_wifi(parser):
    st.subheader("WiFi & Switch Controller")

    tab_aps, tab_ssid, tab_ap_prof, tab_wids, tab_sw, tab_port, tab_nac = st.tabs(
        [
            "Managed FortiAPs",
            "SSIDs",
            "FortiAP Profiles",
            "WIDS Profiles",
            "Managed FortiSwitches",
            "Port Policies",
            "NAC Policies",
        ]
    )

    with tab_aps:
        st.markdown("#### Managed FortiAPs")
        rows = parser.parse_managed_fortiaps()
        if rows:
            st_table(
                rows, key="fg_managed_aps", export_filename="fg_managed_fortiaps.csv"
            )
        else:
            st.info("No managed FortiAPs configured.")

    with tab_ssid:
        st.markdown("#### SSIDs")
        rows = parser.parse_ssids()

        def _hl_ssid(row):
            if str(row.get("Status", "")).lower() == "disable":
                return ["background-color:#fff3cd"] * len(row)
            return [""] * len(row)

        if rows:
            st_table(
                rows, key="fg_ssids", style_fn=_hl_ssid, export_filename="fg_ssids.csv"
            )
        else:
            st.info("No SSIDs configured.")

    with tab_ap_prof:
        st.markdown("#### FortiAP Profiles")
        rows = parser.parse_fortiap_profiles()
        if rows:
            st_table(
                rows, key="fg_ap_profiles", export_filename="fg_fortiap_profiles.csv"
            )
        else:
            st.info("No FortiAP profiles configured.")

    with tab_wids:
        st.markdown("#### WIDS Profiles")
        rows = parser.parse_wids_profiles()
        if rows:
            st_table(rows, key="fg_wids", export_filename="fg_wids_profiles.csv")
        else:
            st.info("No WIDS profiles configured.")

    with tab_sw:
        st.markdown("#### Managed FortiSwitches")
        rows = parser.parse_managed_switches()
        if rows:
            st_table(rows, key="fg_switches", export_filename="fg_managed_switches.csv")
        else:
            st.info("No managed FortiSwitches configured.")

    with tab_port:
        st.markdown("#### FortiSwitch Port Policies")
        rows = parser.parse_switch_port_policies()
        if not rows:
            st.info("No port policies configured.")
        else:
            # searchable summary table at top
            st_table(
                rows, key="fg_port_policies", export_filename="fg_port_policies.csv"
            )
            st.divider()
            # detail expanders
            for row in rows:
                with st.expander(f"Policy: **{row['Name']}**"):
                    c1, c2, c3 = st.columns(3)
                    c1.metric("User Groups", row.get("User Groups", "-"))
                    c2.metric("Guest VLAN", row.get("Guest VLAN", "-"))
                    c3.metric("Auth Delay", f"{row.get('Guest Auth Delay','30')}s")
                    st.markdown("---")
                    _toggle_badge(
                        "MAC Authentication Bypass",
                        row.get("MAC Auth Bypass", "Disable"),
                    )
                    st.markdown("")
                    _toggle_badge(
                        "EAP Pass Through", row.get("EAP Pass Through", "Disable")
                    )
                    st.markdown("")
                    _toggle_badge(
                        "Override RADIUS Timeout", row.get("Override RADIUS", "Disable")
                    )

    with tab_nac:
        st.markdown("#### NAC Policies")
        rows = parser.parse_nac_policies()
        if rows:
            st_table(rows, key="fg_nac", export_filename="fg_nac_policies.csv")
        else:
            st.info("No NAC policies configured.")
