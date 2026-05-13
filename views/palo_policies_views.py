"""Palo Alto Policies view."""

import streamlit as st
import pandas as pd
from parsers.palo_policies import PaloPoliciesParser


def _show_policy_table(rows, empty="No rules configured."):
    """Render policy table with colour coding: disabled=red, panorama=purple, normal=white."""
    if not rows:
        st.info(empty)
        return
    df = pd.DataFrame(rows)
    display_cols = [c for c in df.columns if not c.startswith("_")]
    df_disp = df[display_cols].copy()
    disabled_mask = df.get("_disabled", pd.Series([False] * len(df))).tolist()
    panorama_mask = df.get("_panorama", pd.Series([False] * len(df))).tolist()

    def hl(row):
        idx = row.name
        if idx < len(disabled_mask) and disabled_mask[idx]:
            return ["background-color:#fdecea;color:#999"] * len(row)
        if idx < len(panorama_mask) and panorama_mask[idx]:
            return ["background-color:#f3e5f5"] * len(row)
        return [""] * len(row)

    st.dataframe(
        df_disp.style.apply(hl, axis=1), use_container_width=True, hide_index=True
    )

    dis_count = sum(1 for d in disabled_mask if d)
    pan_count = sum(1 for p in panorama_mask if p)
    total = len(rows)
    caption = f"Total: {total} | ✅ {total-dis_count} enabled | 🔴 {dis_count} disabled"
    if pan_count:
        caption += f" | 🟣 {pan_count} Panorama-managed"
    st.caption(caption)


def _legend():
    st.markdown(
        '<div style="display:flex;gap:16px;margin-bottom:8px;font-size:12px">'
        + "<span>⬜ Enabled</span>"
        + '<span style="background:#fdecea;padding:1px 8px;border-radius:4px">🔴 Disabled</span>'
        + '<span style="background:#f3e5f5;padding:1px 8px;border-radius:4px">🟣 Panorama</span>'
        + "</div>",
        unsafe_allow_html=True,
    )


def _test_policy_match_widget(parser, policy_type):
    with st.expander("🔍 Test Policy Match", expanded=False):
        zones = ["any"] + parser.get_zones_list()
        intfs = ["any"] + (getattr(parser, "get_interfaces_list", lambda: [])())

        # UI Layout for 9 criteria
        col1, col2 = st.columns(2)
        with col1:
            src_z = st.selectbox("Source Zone", zones, key=f"sz_{policy_type}")
            src_i = st.selectbox("Source Interface", intfs, key=f"si_{policy_type}")
            src_ip = st.text_input(
                "Source IP", placeholder="10.0.0.1", key=f"sip_{policy_type}"
            )
            src_u = st.text_input("Source User", value="any", key=f"su_{policy_type}")

        with col2:
            dst_z = st.selectbox("Destination Zone", zones, key=f"dz_{policy_type}")
            dst_i = st.selectbox("Dest Interface", intfs, key=f"di_{policy_type}")
            dst_ip = st.text_input(
                "Destination IP", placeholder="8.8.8.8", key=f"dip_{policy_type}"
            )
            dst_p = st.text_input("Dest Port", value="443", key=f"dp_{policy_type}")

        proto = st.selectbox(
            "Protocol", ["tcp", "udp", "icmp", "any"], key=f"pr_{policy_type}"
        )

        if st.button("Trace Traffic Match", key=f"btn_run_{policy_type}"):
            if not src_ip or not dst_ip:
                st.error("Please enter both Source and Destination IP addresses.")
            else:
                # Call the updated parser logic
                res = parser.test_policy_match(
                    policy_type,
                    src_z,
                    dst_z,
                    src_i,
                    dst_i,
                    src_ip,
                    dst_ip,
                    src_u,
                    dst_p,
                    proto,
                )

                if res["matched"]:
                    st.success(f"✅ **Traffic Matched!**")
                    st.write(f"**Result:** {res['reason']}")
                    st.table(pd.DataFrame([res["rule"]]))
                else:
                    st.error(f"🚫 **Traffic Dropped**")
                    st.info(res["reason"])


def render_pa_policies(parser: PaloPoliciesParser):
    st.markdown("### 📋 Policies")

    tabs = st.tabs(
        [
            "Security",
            "NAT",
            "QoS",
            "Policy Based Forwarding",
            "Decryption",
            "Tunnel Inspection",
            "App Override",
            "Authentication",
            "DoS Protection",
            "SD-WAN",
        ]
    )

    with tabs[0]:
        st.markdown("#### 🛡️ Security Policies")
        _legend()
        _test_policy_match_widget(parser, "security")
        _show_policy_table(parser.get_security_rules())

    with tabs[1]:
        st.markdown("#### 🔄 NAT Rules")
        _legend()
        _test_policy_match_widget(parser, "nat")
        _show_policy_table(parser.get_nat_rules())

    with tabs[2]:
        st.markdown("#### 📶 QoS Rules")
        _legend()
        _test_policy_match_widget(parser, "qos")
        _show_policy_table(parser.get_qos_rules())

    with tabs[3]:
        st.markdown("#### ↗️ Policy Based Forwarding")
        _legend()
        _test_policy_match_widget(parser, "pbf")
        _show_policy_table(parser.get_pbf_rules())

    with tabs[4]:
        st.markdown("#### 🔓 Decryption Policies")
        _legend()
        _test_policy_match_widget(parser, "decryption")
        _show_policy_table(parser.get_decryption_rules())

    with tabs[5]:
        st.markdown("#### 🔭 Tunnel Inspection")
        _legend()
        _show_policy_table(parser.get_tunnel_inspection_rules())

    with tabs[6]:
        st.markdown("#### 🔀 Application Override")
        _legend()
        _show_policy_table(parser.get_app_override_rules())

    with tabs[7]:
        st.markdown("#### 🔑 Authentication")
        _legend()
        _test_policy_match_widget(parser, "auth")
        _show_policy_table(parser.get_auth_rules())

    with tabs[8]:
        st.markdown("#### 🛡️ DoS Protection")
        _legend()
        _test_policy_match_widget(parser, "dos")
        _show_policy_table(parser.get_dos_rules())

    with tabs[9]:
        st.markdown("#### 🌐 SD-WAN Rules")
        _legend()
        _show_policy_table(parser.get_sdwan_rules())


def _test_policy_match(parser, policy_type):
    import streamlit as st

    with st.expander("🔍 Test Policy Match", expanded=False):
        zones = ["any"] + parser.get_zones_list()
        c1, c2 = st.columns(2)
        with c1:
            src_zone = st.selectbox("Source Zone", zones, key=f"sz_{policy_type}")
            src_ip = st.text_input("Source IP", key=f"si_{policy_type}")
        with c2:
            dst_zone = st.selectbox("Destination Zone", zones, key=f"dz_{policy_type}")
            dst_ip = st.text_input("Destination IP", key=f"di_{policy_type}")

        dst_port = st.text_input("Port", value="443", key=f"dp_{policy_type}")

        if st.button("Run Match", key=f"btn_{policy_type}"):
            res = parser.test_policy_match(
                policy_type, src_zone, dst_zone, src_ip, dst_ip, dst_port
            )
            st.write(res["reason"])
            if res["rule"]:
                st.json(res["rule"])
