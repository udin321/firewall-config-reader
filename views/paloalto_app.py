
import streamlit as st
import pandas as pd
from parsers.paloalto_parser import PaloAltoParser


# ── Helpers ─────────────────────────────────────────────────────────────────

def _show(rows, empty="No data.", height=None):
    if not rows:
        st.info(empty)
        return
    df = pd.DataFrame(rows)
    # Remove internal columns
    display_cols = [c for c in df.columns if not c.startswith("_")]
    df = df[display_cols]
    kwargs = {"use_container_width": True, "hide_index": True}
    if height:
        kwargs["height"] = height
    st.dataframe(df, **kwargs)


def _show_with_disabled(rows, empty="No rules configured."):
    """Show table with disabled rows highlighted red."""
    if not rows:
        st.info(empty)
        return
    df = pd.DataFrame(rows)
    display_cols = [c for c in df.columns if not c.startswith("_")]
    df_disp = df[display_cols].copy()
    disabled_mask = df.get("_disabled", pd.Series([False]*len(df))).tolist()

    def hl(row):
        idx = row.name
        if idx < len(disabled_mask) and disabled_mask[idx]:
            return ["background-color:#fdecea;color:#999"] * len(row)
        return [""] * len(row)

    st.dataframe(
        df_disp.style.apply(hl, axis=1),
        use_container_width=True, hide_index=True
    )
    dis_count = sum(1 for d in disabled_mask if d)
    total = len(rows)
    st.caption(f"Total: {total} | ✅ {total - dis_count} enabled | 🔴 {dis_count} disabled")


def _badge(text, color="#2980b9"):
    return f'<span style="background:{color};color:white;padding:2px 10px;border-radius:10px;font-size:12px;font-weight:bold">{text}</span>'


def _section_header(title, icon=""):
    st.markdown(f"### {icon} {title}")


# ── Test Policy Match Widget ─────────────────────────────────────────────────

def _test_policy_match(parser, policy_type):
    with st.expander("🔍 Test Policy Match", expanded=False):
        zones = ["any"] + parser.get_zones_list()
        intfs = ["any"] + parser.get_interfaces_list()
        protocols = ["tcp", "udp", "icmp", "any"]

        c1, c2 = st.columns(2)
        with c1:
            src_zone = st.selectbox("Source Zone", zones, key=f"tpm_sz_{policy_type}")
            src_intf = st.selectbox("Source Interface", intfs, key=f"tpm_si_{policy_type}")
            src_ip   = st.text_input("Source IP *", key=f"tpm_sip_{policy_type}")
            src_user = st.text_input("Source User", value="any", key=f"tpm_su_{policy_type}")
        with c2:
            dst_zone = st.selectbox("Destination Zone", zones, key=f"tpm_dz_{policy_type}")
            dst_intf = st.selectbox("Destination Interface", intfs, key=f"tpm_di_{policy_type}")
            dst_ip   = st.text_input("Destination IP *", key=f"tpm_dip_{policy_type}")
            dst_port = st.text_input("Destination Port *", key=f"tpm_dp_{policy_type}")

        proto = st.selectbox("Protocol", protocols, key=f"tpm_proto_{policy_type}")

        if st.button("Find Matching Rules", key=f"tpm_btn_{policy_type}"):
            if not src_ip or not dst_ip or not dst_port:
                st.warning("Source IP, Destination IP and Destination Port are required.")
            else:
                matches = parser.test_policy_match(
                    policy_type, src_zone, dst_zone, src_ip, dst_ip, dst_port, src_user, proto
                )
                if matches:
                    st.success(f"Found {len(matches)} matching rule(s):")
                    for m in matches:
                        st.markdown(f"- **{m}**")
                else:
                    st.warning("No matching rules found.")


# ── Dashboard ────────────────────────────────────────────────────────────────

def render_dashboard(parser):
    info = parser.get_system_info()
    ha   = parser.get_ha_info()

    st.markdown("## 📊 Dashboard")

    # General Information
    st.markdown("### 🖥️ General Information")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f'<div style="background:#eaf4fb;border-radius:10px;padding:14px;margin-bottom:10px">'
                    f'<div style="font-size:11px;color:#666">Hostname</div>'
                    f'<div style="font-size:18px;font-weight:bold;color:#2c3e50">{info.get("hostname","-")}</div></div>',
                    unsafe_allow_html=True)
        st.metric("Software Version", info.get("software_version", "-"))
        st.metric("Timezone",         info.get("timezone", "-"))
    with col2:
        st.metric("MGT IP Address",  info.get("ip_address", "-"))
        st.metric("MGT Netmask",     info.get("netmask", "-"))
        st.metric("MGT Default GW",  info.get("default_gateway", "-") or "—")
    with col3:
        st.metric("IPv6 Address",    info.get("ipv6_address", "Unknown"))
        st.metric("IPv6 Link Local", info.get("ipv6_link_local", "Unknown"))
        st.metric("IPv6 Default GW", info.get("ipv6_gateway", "-") or "—")

    c1, c2 = st.columns(2)
    adv_color = "#2ecc71" if info.get("adv_routing") == "On" else "#e74c3c"
    dup_color  = "#2ecc71" if info.get("dup_ip") == "Enable" else "#95a5a6"
    c1.markdown(f'<div style="background:#f8f9fa;border-radius:10px;padding:12px">'
                f'<div style="font-size:11px;color:#666">Advanced Routing</div>'
                f'<span style="background:{adv_color};color:white;padding:3px 12px;border-radius:10px;font-weight:bold">'
                f'{info.get("adv_routing","Off")}</span></div>', unsafe_allow_html=True)
    c2.markdown(f'<div style="background:#f8f9fa;border-radius:10px;padding:12px">'
                f'<div style="font-size:11px;color:#666">Duplicate IP Detection</div>'
                f'<span style="background:{dup_color};color:white;padding:3px 12px;border-radius:10px;font-weight:bold">'
                f'{info.get("dup_ip","Disable")}</span></div>', unsafe_allow_html=True)

    st.divider()

    # HA
    st.markdown("### 🔗 High Availability")
    if not ha.get("enabled"):
        st.markdown(
            '<div style="background:#f8f9fa;border-radius:12px;padding:20px;text-align:center">'
            '<div style="font-size:28px">🖥️</div>'
            '<div style="font-size:16px;font-weight:bold;color:#2c3e50;margin-top:8px">Not Enabled</div>'
            '<div style="color:#888;font-size:13px">Standalone mode</div></div>',
            unsafe_allow_html=True)
    else:
        mode = ha.get("mode", "active-passive")
        mode_label = "Active-Passive" if mode == "active-passive" else "Active-Active"
        color = "#27ae60" if mode == "active-passive" else "#2980b9"
        st.markdown(
            f'<div style="background:{color}15;border:2px solid {color};border-radius:12px;padding:16px">'
            f'<div style="font-size:18px;font-weight:bold;color:{color}">{mode_label}</div></div>',
            unsafe_allow_html=True)
        c1, c2, c3 = st.columns(3)
        c1.metric("Mode",         mode_label)
        c2.metric("Peer IP",      ha.get("peer_ip", "-"))
        c3.metric("HA1 IP",       ha.get("ha1_ip", "-"))


# ── Policies ─────────────────────────────────────────────────────────────────

def render_policies(parser):
    st.markdown("## 📋 Policies")

    tabs = st.tabs([
        "Security", "NAT", "QoS", "Policy Based Forwarding",
        "Decryption", "Tunnel Inspection", "App Override",
        "Authentication", "DoS Protection", "SD-WAN"
    ])

    with tabs[0]:
        _section_header("Security Policies", "🛡️")
        _test_policy_match(parser, "security")
        _show_with_disabled(parser.get_security_rules(), "No security rules configured.")

    with tabs[1]:
        _section_header("NAT Rules", "🔄")
        _test_policy_match(parser, "nat")
        _show_with_disabled(parser.get_nat_rules(), "No NAT rules configured.")

    with tabs[2]:
        _section_header("QoS Rules", "📶")
        _test_policy_match(parser, "qos")
        _show_with_disabled(parser.get_qos_rules(), "No QoS rules configured.")

    with tabs[3]:
        _section_header("Policy Based Forwarding", "↗️")
        _test_policy_match(parser, "pbf")
        _show_with_disabled(parser.get_pbf_rules(), "No PBF rules configured.")

    with tabs[4]:
        _section_header("Decryption Policies", "🔓")
        _test_policy_match(parser, "decryption")
        rules = parser.get_decryption_rules()
        if rules:
            _show_with_disabled(rules)
        else:
            st.info("No decryption policies configured.")

    with tabs[5]:
        _section_header("Tunnel Inspection", "🔭")
        rules = parser.get_tunnel_inspection_rules()
        if rules:
            _show_with_disabled(rules)
        else:
            st.info("No tunnel inspection rules configured.")

    with tabs[6]:
        _section_header("Application Override", "🔀")
        rules = parser.get_app_override_rules()
        if rules:
            _show_with_disabled(rules)
        else:
            st.info("No application override rules configured.")

    with tabs[7]:
        _section_header("Authentication", "🔑")
        _test_policy_match(parser, "auth")
        rules = parser.get_auth_rules()
        if rules:
            _show_with_disabled(rules)
        else:
            st.info("No authentication rules configured.")

    with tabs[8]:
        _section_header("DoS Protection", "🛡️")
        _test_policy_match(parser, "dos")
        rules = parser.get_dos_rules()
        if rules:
            _show_with_disabled(rules)
        else:
            st.info("No DoS protection rules configured.")

    with tabs[9]:
        _section_header("SD-WAN Rules", "🌐")
        _show_with_disabled(parser.get_sdwan_rules(), "No SD-WAN rules configured.")


# ── Objects ──────────────────────────────────────────────────────────────────

def render_objects(parser):
    st.markdown("## 📦 Objects")

    tabs = st.tabs([
        "Addresses", "Address Groups", "Services",
        "Service Groups", "Tags", "Security Profiles",
        "URL Categories"
    ])

    with tabs[0]:
        _section_header("Addresses", "📍")
        rows = parser.get_addresses()
        if rows:
            df = pd.DataFrame(rows)
            col_filter = st.selectbox("Filter by Type", ["All"] + sorted(df["Type"].unique().tolist()), key="addr_filter")
            if col_filter != "All":
                df = df[df["Type"] == col_filter]
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.caption(f"Total: {len(rows)} addresses")
        else:
            st.info("No addresses configured.")

    with tabs[1]:
        _section_header("Address Groups", "📂")
        _show(parser.get_address_groups(), "No address groups configured.")

    with tabs[2]:
        _section_header("Services", "⚙️")
        _show(parser.get_services(), "No services configured.")

    with tabs[3]:
        _section_header("Service Groups", "⚙️")
        _show(parser.get_service_groups(), "No service groups configured.")

    with tabs[4]:
        _section_header("Tags", "🏷️")
        _show(parser.get_tags(), "No tags configured.")

    with tabs[5]:
        _section_header("Security Profiles", "🔐")
        sec_profiles = parser.get_security_profiles()
        if not sec_profiles:
            st.info("No security profiles configured.")
        else:
            # Profile Groups
            pg = sec_profiles.get("profile-groups", {})
            if pg:
                st.markdown("#### Profile Groups")
                COLOURS = {"None": "#95a5a6"}
                for name, parts in pg.items():
                    with st.expander(f"**{name}**"):
                        cols = st.columns(len(parts))
                        for col, (ptype, pval) in zip(cols, parts.items()):
                            bg = "#27ae60" if pval != "None" else "#95a5a6"
                            col.markdown(
                                f'<div style="text-align:center;padding:6px">'
                                f'<div style="font-size:10px;color:#666">{ptype.replace("-"," ").title()}</div>'
                                f'<span style="background:{bg};color:white;padding:2px 8px;'
                                f'border-radius:8px;font-size:11px">{pval}</span></div>',
                                unsafe_allow_html=True)
            # Individual profiles
            for ptype in ["virus","spyware","vulnerability","url-filtering","wildfire-analysis","file-blocking"]:
                entries = sec_profiles.get(ptype, [])
                if entries:
                    st.markdown(f"**{ptype.replace('-',' ').title()}:** {', '.join(entries)}")

    with tabs[6]:
        _section_header("Custom URL Categories", "🌐")
        _show(parser.get_custom_url_categories(), "No custom URL categories configured.")


# ── Network ──────────────────────────────────────────────────────────────────

def render_network(parser):
    st.markdown("## 🌐 Network")

    tabs = st.tabs(["Interfaces", "Zones", "Virtual Router",
                    "Static Routes", "SD-WAN", "GlobalProtect"])

    with tabs[0]:
        _section_header("Interfaces", "🔌")
        rows = parser.get_interfaces()
        if rows:
            df = pd.DataFrame(rows)
            display = [c for c in df.columns if c != "Parent"]

            def hl_intf(row):
                if "Sub" in str(row.get("Type", "")):
                    return ["background-color:#f8f9fa"] * len(row)
                if row.get("Type") == "Aggregate":
                    return ["background-color:#eaf4fb;font-weight:bold"] * len(row)
                return [""] * len(row)

            st.dataframe(df[display].style.apply(hl_intf, axis=1),
                         use_container_width=True, hide_index=True)
        else:
            st.info("No interfaces found.")

    with tabs[1]:
        _section_header("Zones", "🗺️")
        _show(parser.get_zones(), "No zones configured.")

    with tabs[2]:
        _section_header("Virtual Router", "🔀")
        vr = parser.get_virtual_router_info()
        if vr:
            st.metric("Virtual Router", vr.get("name", "default"))
            st.markdown(f"**Interfaces:** {', '.join(vr.get('interfaces', []))}")
            st.markdown("**Routing Protocols:**")
            for proto, info in vr.get("protocols", {}).items():
                enabled = info.get("enabled", False)
                color = "#2ecc71" if enabled else "#e74c3c"
                st.markdown(
                    f'<span style="background:{color};color:white;padding:2px 10px;'
                    f'border-radius:10px;font-size:12px;margin-right:8px">{proto.upper()}: '
                    f'{"ON" if enabled else "OFF"}</span>',
                    unsafe_allow_html=True)
        else:
            st.info("No virtual router configured.")

    with tabs[3]:
        _section_header("Static Routes", "🗺️")
        rows = parser.get_static_routes()
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            st.caption(f"Total: {len(rows)} routes")
        else:
            st.info("No static routes configured.")

    with tabs[4]:
        _section_header("SD-WAN Interface Profiles", "📡")
        _show(parser.get_sdwan_interfaces(), "No SD-WAN interface profiles configured.")

    with tabs[5]:
        _section_header("GlobalProtect", "🔒")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("##### Portals")
            _show(parser.get_globalprotect_portals(), "No portals configured.")
        with c2:
            st.markdown("##### Gateways")
            _show(parser.get_globalprotect_gateways(), "No gateways configured.")


# ── Device ───────────────────────────────────────────────────────────────────

def render_device(parser):
    st.markdown("## ⚙️ Device")

    tabs = st.tabs(["Administrators", "System Settings", "DNS & NTP", "Syslog"])

    with tabs[0]:
        _section_header("Administrators", "👤")
        _show(parser.get_admins(), "No administrators configured.")

    with tabs[1]:
        _section_header("System Settings", "⚙️")
        info = parser.get_system_info()
        c1, c2, c3 = st.columns(3)
        c1.metric("Hostname",         info.get("hostname", "-"))
        c2.metric("Timezone",         info.get("timezone", "-"))
        c3.metric("Software Version", info.get("software_version", "-"))
        c1.metric("MGT IP",           info.get("ip_address", "-"))
        c2.metric("MGT Netmask",      info.get("netmask", "-"))
        c3.metric("Default GW",       info.get("default_gateway", "-") or "—")

    with tabs[2]:
        _section_header("DNS & NTP", "🕐")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("##### DNS Servers")
            dns = parser.get_dns()
            st.metric("Primary DNS",   dns.get("primary", "-"))
            st.metric("Secondary DNS", dns.get("secondary", "-"))
        with c2:
            st.markdown("##### NTP Servers")
            ntp = parser.get_ntp()
            st.metric("Primary NTP",   ntp.get("primary", "-"))
            st.metric("Secondary NTP", ntp.get("secondary", "-"))

    with tabs[3]:
        _section_header("Syslog", "📜")
        _show(parser.get_syslog(), "No syslog servers configured.")


# ── Main Palo Alto App ───────────────────────────────────────────────────────

def run_paloalto_app(content: str):
    try:
        parser = PaloAltoParser(content)
    except Exception as e:
        st.error(f"Failed to parse XML: {e}")
        return

    info = parser.get_system_info()

    # Header
    st.markdown(
        f'<div style="background:linear-gradient(135deg,#1a1a2e,#16213e);'
        f'color:white;padding:20px 28px;border-radius:12px;margin-bottom:20px">'
        f'<div style="display:flex;align-items:center;gap:16px">'
        f'<div style="font-size:36px">🔥</div>'
        f'<div><div style="font-size:22px;font-weight:bold">{info.get("hostname","Palo Alto")}</div>'
        f'<div style="font-size:13px;opacity:0.7">PAN-OS {info.get("software_version","")} | '
        f'{info.get("ip_address","")} | {info.get("timezone","")}</div></div></div></div>',
        unsafe_allow_html=True
    )

    tab_names = ["🏠 Dashboard", "📋 Policies", "📦 Objects", "🌐 Network", "⚙️ Device"]
    tabs = st.tabs(tab_names)

    with tabs[0]:
        render_dashboard(parser)
    with tabs[1]:
        render_policies(parser)
    with tabs[2]:
        render_objects(parser)
    with tabs[3]:
        render_network(parser)
    with tabs[4]:
        render_device(parser)
