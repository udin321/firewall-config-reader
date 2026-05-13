"""Palo Alto Dashboard view."""
import streamlit as st
from parsers.paloalto import PaloAltoParser


def render_pa_dashboard(parser: PaloAltoParser):
    info = parser.get_system_info()
    ha   = parser.get_ha_info()

    # ── General Information ──────────────────────────────────────────
    st.markdown("### 🖥️ General Information")

    # Hostname hero card
    st.markdown(
        f'<div style="background:linear-gradient(135deg,#1a1a2e,#16213e);color:white;' +
        f'padding:16px 24px;border-radius:12px;margin-bottom:16px">' +
        f'<div style="font-size:11px;opacity:0.6;text-transform:uppercase;letter-spacing:1px">Device Name</div>' +
        f'<div style="font-size:24px;font-weight:bold">{info.get("hostname","Unknown")}</div>' +
        f'<div style="font-size:12px;opacity:0.7;margin-top:4px">PAN-OS {info.get("software_version","")} | {info.get("timezone","")}</div>' +
        f'</div>',
        unsafe_allow_html=True
    )

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("MGT IP Address",  info.get("ip_address", "-"))
        st.metric("MGT Netmask",     info.get("netmask", "-"))
        st.metric("MGT Default GW",  info.get("default_gateway", "-") or "—")
    with c2:
        st.metric("IPv6 Address",    info.get("ipv6_address", "Unknown"))
        st.metric("IPv6 Link Local", info.get("ipv6_link_local", "Unknown"))
        st.metric("IPv6 Default GW", info.get("ipv6_gateway", "") or "—")
    with c3:
        st.metric("Software Version", info.get("software_version", "-"))
        # Advanced routing badge
        ar_color = "#2ecc71" if info.get("adv_routing") == "On" else "#e74c3c"
        di_color = "#2ecc71" if info.get("dup_ip") == "Enable" else "#95a5a6"
        st.markdown(
            f'<div style="background:#f8f9fa;border-radius:10px;padding:10px;margin-top:8px">' +
            f'<div style="font-size:11px;color:#666;margin-bottom:6px">Feature Flags</div>' +
            f'<span style="background:{ar_color};color:white;padding:2px 10px;border-radius:10px;font-size:12px;font-weight:bold;margin-right:6px">Advanced Routing: {info.get("adv_routing","Off")}</span><br><br>' +
            f'<span style="background:{di_color};color:white;padding:2px 10px;border-radius:10px;font-size:12px;font-weight:bold">Duplicate IP: {info.get("dup_ip","Disable")}</span>' +
            f'</div>',
            unsafe_allow_html=True
        )

    st.divider()

    # ── High Availability ────────────────────────────────────────────
    st.markdown("### 🔗 High Availability")
    if not ha.get("enabled"):
        st.markdown(
            '<div style="background:#f8f9fa;border-radius:12px;padding:24px;text-align:center">' +
            '<div style="font-size:32px">🖥️</div>' +
            '<div style="font-size:16px;font-weight:bold;color:#2c3e50;margin-top:8px">Not Enabled</div>' +
            '<div style="color:#888;font-size:13px">Standalone mode</div>' +
            '</div>',
            unsafe_allow_html=True
        )
    else:
        mode = ha.get("mode", "active-passive")
        mode_label = "Active-Passive" if mode == "active-passive" else "Active-Active"
        mode_color = "#27ae60" if mode == "active-passive" else "#2980b9"

        if mode == "active-passive":
            states = ["Active", "Passive"]
        else:
            states = ["Active-Primary", "Active-Secondary"]

        st.markdown(
            f'<div style="background:{mode_color}15;border:2px solid {mode_color};' +
            f'border-radius:12px;padding:16px;margin-bottom:16px">' +
            f'<div style="font-size:18px;font-weight:bold;color:{mode_color}">{mode_label}</div>' +
            f'<div style="font-size:12px;color:#666;margin-top:4px">Group ID: {ha.get("group_id","-")}</div>' +
            f'</div>',
            unsafe_allow_html=True
        )
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Local State",  states[0])
        c2.metric("Peer IP",      ha.get("peer_ip", "-"))
        c3.metric("HA1 Interface", ha.get("ha1_port", "-"))
        c4.metric("HA1 IP",       ha.get("ha1_ip", "-"))
