"""Palo Alto — Policies tab. Every table: search + column filter + CSV via st_table."""

import streamlit as st
import pandas as pd
from parsers.palo_policies import PaloPoliciesParser
from views.table_utils import st_table

# ── helpers ────────────────────────────────────────────────────────────────────


def _legend():
    st.markdown(
        '<div style="display:flex;gap:14px;margin-bottom:8px;font-size:12px;flex-wrap:wrap">'
        "<span>⬜ Enabled</span>"
        "<span>🔴 Disabled</span>"
        "<span>🟣 Panorama</span>"
        "</div>",
        unsafe_allow_html=True,
    )


def _policy_style(df: pd.DataFrame):
    """Returns a style_fn that colours disabled/panorama rows."""
    disabled_mask = df.get("_disabled", pd.Series([False] * len(df))).tolist()
    panorama_mask = df.get("_panorama", pd.Series([False] * len(df))).tolist()

    def _fn(row):
        idx = row.name
        if idx < len(disabled_mask) and disabled_mask[idx]:
            return ["background-color:#fdecea;color:#999"] * len(row)
        if idx < len(panorama_mask) and panorama_mask[idx]:
            return ["background-color:#f3e5f5"] * len(row)
        return [""] * len(row)

    return _fn


def _show_policy(rows, key: str, label: str = ""):
    if not rows:
        st.info(f"No {label or 'rules'} configured.")
        return
    df = pd.DataFrame(rows)
    display_cols = [c for c in df.columns if not c.startswith("_")]
    df_disp = df[display_cols].copy()

    dis = sum(1 for r in rows if r.get("_disabled"))
    pan = sum(1 for r in rows if r.get("_panorama"))
    cap = f"Total: {len(rows)} | ✅ {len(rows)-dis} enabled | 🔴 {dis} disabled"
    if pan:
        cap += f" | 🟣 {pan} Panorama"

    st_table(
        df_disp,
        key=key,
        style_fn=_policy_style(df),
        caption=cap,
        export_filename=f"{key}.csv",
    )


def _test_match_widget(parser, policy_type):
    with st.expander("🔍 Test Policy Match", expanded=False):
        zones = ["any"] + parser.get_zones_list()
        intfs = ["any"] + (getattr(parser, "get_interfaces_list", lambda: [])())
        c1, c2 = st.columns(2)
        with c1:
            src_z = st.selectbox("Source Zone", zones, key=f"sz_{policy_type}")
            src_i = st.selectbox("Source Interface", intfs, key=f"si_{policy_type}")
            src_ip = st.text_input(
                "Source IP", placeholder="10.0.0.1", key=f"sip_{policy_type}"
            )
            src_u = st.text_input("Source User", value="any", key=f"su_{policy_type}")
        with c2:
            dst_z = st.selectbox("Destination Zone", zones, key=f"dz_{policy_type}")
            dst_i = st.selectbox(
                "Destination Interface", intfs, key=f"di_{policy_type}"
            )
            dst_ip = st.text_input(
                "Destination IP", placeholder="8.8.8.8", key=f"dip_{policy_type}"
            )
            dst_p = st.text_input("Dest Port", value="443", key=f"dp_{policy_type}")
        proto = st.selectbox(
            "Protocol", ["tcp", "udp", "icmp", "any"], key=f"pr_{policy_type}"
        )

        if st.button("Trace Traffic Match", key=f"btn_{policy_type}"):
            if not src_ip or not dst_ip:
                st.error("Please enter both Source and Destination IP addresses.")
            else:
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
                    st.success("✅ **Traffic Matched!**")
                    st.write(f"**Result:** {res['reason']}")
                    if res.get("rule"):
                        st_table(
                            [res["rule"]],
                            key=f"match_result_{policy_type}",
                            export_filename=f"pa_match_{policy_type}.csv",
                        )
                else:
                    st.error("🚫 **Traffic Dropped**")
                    st.info(res["reason"])


# ── main render ────────────────────────────────────────────────────────────────


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
        _test_match_widget(parser, "security")
        _show_policy(parser.get_security_rules(), "pa_security_rules", "Security rules")

    with tabs[1]:
        st.markdown("#### 🔄 NAT Rules")
        _legend()
        _test_match_widget(parser, "nat")
        _show_policy(parser.get_nat_rules(), "pa_nat_rules", "NAT rules")

    with tabs[2]:
        st.markdown("#### 📶 QoS Rules")
        _legend()
        _show_policy(parser.get_qos_rules(), "pa_qos_rules", "QoS rules")

    with tabs[3]:
        st.markdown("#### ↗️ Policy Based Forwarding")
        _legend()
        _test_match_widget(parser, "pbf")
        _show_policy(parser.get_pbf_rules(), "pa_pbf_rules", "PBF rules")

    with tabs[4]:
        st.markdown("#### 🔓 Decryption Policies")
        _legend()
        _test_match_widget(parser, "decryption")
        _show_policy(
            parser.get_decryption_rules(), "pa_decrypt_rules", "Decryption rules"
        )

    with tabs[5]:
        st.markdown("#### 🔭 Tunnel Inspection")
        _legend()
        _show_policy(
            parser.get_tunnel_inspection_rules(),
            "pa_tunnel_rules",
            "Tunnel inspection rules",
        )

    with tabs[6]:
        st.markdown("#### 🔀 Application Override")
        _legend()
        _show_policy(
            parser.get_app_override_rules(), "pa_appov_rules", "App override rules"
        )

    with tabs[7]:
        st.markdown("#### 🔑 Authentication")
        _legend()
        _test_match_widget(parser, "auth")
        _show_policy(parser.get_auth_rules(), "pa_auth_rules", "Authentication rules")

    with tabs[8]:
        st.markdown("#### 🛡️ DoS Protection")
        _legend()
        _test_match_widget(parser, "dos")
        _show_policy(parser.get_dos_rules(), "pa_dos_rules", "DoS rules")

    with tabs[9]:
        st.markdown("#### 🌐 SD-WAN Rules")
        _legend()
        _show_policy(parser.get_sdwan_rules(), "pa_sdwan_rules", "SD-WAN rules")
