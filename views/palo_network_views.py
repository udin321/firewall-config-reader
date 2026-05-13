"""Palo Alto Network views – full overhaul with all enhancements."""

import streamlit as st
import pandas as pd
from parsers.palo_network import PaloNetworkParser


def _show(rows, empty="Not configured.", key=None):
    if not rows:
        st.info(empty)
        return
    df = pd.DataFrame(rows)
    display_cols = [c for c in df.columns if not c.startswith("_")]
    kw = {"use_container_width": True, "hide_index": True}
    if key:
        kw["key"] = key
    st.dataframe(df[display_cols], **kw)
    st.caption(f"Total: {len(rows)} entries")


def render_pa_network(parser: PaloNetworkParser):
    st.markdown("### 🌐 Network")

    tabs = st.tabs(
        [
            "Interfaces",
            "Zones",
            "VLANs",
            "Virtual Wires",
            "Virtual Router",
            "IPSec & GRE Tunnels",
            "DHCP",
            "DNS Proxy",
            "GlobalProtect",
            "QoS",
            "Network Profiles",
            "SD-WAN Profiles",
        ]
    )

    # ── Interfaces ────────────────────────────────────────────
    with tabs[0]:
        st.markdown("#### 🔌 Interfaces")
        intf_tabs = st.tabs(
            ["Ethernet / Aggregate", "VLAN", "Loopback", "Tunnel", "SD-WAN"]
        )
        with intf_tabs[0]:
            rows = parser.get_ethernet_interfaces()
            if rows:
                df = pd.DataFrame(rows)

                def hl(row):
                    t = str(row.get("Type", ""))
                    if t == "HA":
                        return ["background-color:#fef3e2"] * len(row)
                    if "Aggregate (Parent)" in t:
                        return ["background-color:#eaf4fb"] * len(row)
                    if "Sub-Interface" in t:
                        return ["background-color:#f8f9fa"] * len(row)
                    if t == "Virtual Wire":
                        return ["background-color:#f3e5f5"] * len(row)
                    return [""] * len(row)

                st.dataframe(
                    df.style.apply(hl, axis=1),
                    use_container_width=True,
                    hide_index=True,
                )
                st.caption(f"Total: {len(rows)} entries")
            else:
                st.info("No ethernet/aggregate interfaces.")
        with intf_tabs[1]:
            _show(parser.get_vlan_interfaces(), "No VLAN interfaces.", key="vlan_intf")
        with intf_tabs[2]:
            _show(
                parser.get_loopback_interfaces(),
                "No loopback interfaces.",
                key="lo_intf",
            )
        with intf_tabs[3]:
            _show(
                parser.get_tunnel_interfaces(), "No tunnel interfaces.", key="tun_intf"
            )
        with intf_tabs[4]:
            _show(
                parser.get_sdwan_interfaces(), "No SD-WAN interfaces.", key="sdwan_intf"
            )

    # ── Zones ─────────────────────────────────────────────────
    with tabs[1]:
        st.markdown("#### 🗺️ Zones")
        rows = parser.get_zones()
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            st.caption(f"Total: {len(rows)} zones")
        else:
            st.info("No zones configured.")

    # ── VLANs ─────────────────────────────────────────────────
    with tabs[2]:
        st.markdown("#### 🔗 VLANs")
        _show(parser.get_vlans(), "No VLAN objects.", key="vlans")

    # ── Virtual Wires ─────────────────────────────────────────
    with tabs[3]:
        st.markdown("#### ↔️ Virtual Wires")
        _show(parser.get_virtual_wires(), "No virtual wires.", key="vwires")

    # ── Virtual Router ────────────────────────────────────────
    with tabs[4]:
        st.markdown("#### 🔀 Virtual Router")
        vrs = parser.get_virtual_routers()
        if not vrs:
            st.info("No virtual routers.")
            return
        df_vr = pd.DataFrame(
            [{k: v for k, v in r.items() if k != "_vr_el"} for r in vrs]
        )
        st.dataframe(df_vr, use_container_width=True, hide_index=True)
        st.caption(f"Total: {len(vrs)} virtual routers")
        for vr_row in vrs:
            detail = parser.get_vr_detail(vr_row["_vr_el"])
            with st.expander(f"📋 {detail['name']} — Details"):
                vr_sub = st.tabs(["General / ECMP", "Static Routes", "BGP"])
                with vr_sub[0]:
                    st.markdown(
                        f"**Interfaces ({len(detail['interfaces'])}):** {', '.join(detail['interfaces'])}"
                    )
                    ad = detail.get("ad", {})
                    if ad:
                        ad_rows = [
                            {"Metric": k.replace("-", " ").title(), "Distance": v}
                            for k, v in ad.items()
                            if v != "-"
                        ]
                        if ad_rows:
                            st.dataframe(
                                pd.DataFrame(ad_rows),
                                use_container_width=True,
                                hide_index=True,
                            )
                    ecmp = detail["ecmp"]
                    enabled = ecmp.get("enabled") == "yes"
                    st.markdown(
                        f"**ECMP:** {'✅ Enabled' if enabled else '❌ Disabled'}"
                    )
                    if enabled:
                        c1, c2, c3 = st.columns(3)
                        c1.metric("Method", ecmp.get("method", "-"))
                        c2.metric("Symmetric Return", ecmp.get("symmetric_return", "-"))
                        c3.metric("Strict Source", ecmp.get("strict_source", "-"))
                with vr_sub[1]:
                    sr = detail.get("static_v4", [])
                    if sr:
                        df = pd.DataFrame(sr)

                        def hl_sr(row):
                            return (
                                ["background-color:#e8f8f0"] * len(row)
                                if row.get("Path Mon") == "yes"
                                else [""] * len(row)
                            )

                        st.dataframe(
                            df.style.apply(hl_sr, axis=1),
                            use_container_width=True,
                            hide_index=True,
                        )
                        st.caption(f"Total: {len(sr)} IPv4 routes")
                    else:
                        st.info("No static routes.")
                with vr_sub[2]:
                    bgp = detail.get("bgp", {})
                    if bgp:
                        c1, c2, c3 = st.columns(3)
                        c1.metric("Enabled", bgp.get("Enabled", "-"))
                        c2.metric("Local AS", bgp.get("Local AS", "-"))
                        c3.metric("GR", bgp.get("Graceful Restart", "-"))
                    else:
                        st.info("BGP not configured.")

    # ── IPSec & GRE Tunnels ───────────────────────────────────
    with tabs[5]:
        st.markdown("#### 🔐 IPSec & GRE Tunnels")
        ipsec_tabs = st.tabs(["IPSec Tunnels", "GRE Tunnels"])
        with ipsec_tabs[0]:
            rows = parser.get_ipsec_tunnels()
            if rows:
                st.dataframe(
                    pd.DataFrame(rows), use_container_width=True, hide_index=True
                )
                st.caption(f"Total: {len(rows)} IPSec tunnels")
            else:
                st.info("No IPSec tunnels configured.")
        with ipsec_tabs[1]:
            rows = parser.get_gre_tunnels()
            if rows:
                st.dataframe(
                    pd.DataFrame(rows), use_container_width=True, hide_index=True
                )
                st.caption(f"Total: {len(rows)} GRE tunnels")
            else:
                st.info("No GRE tunnels configured.")

    # ── DHCP ──────────────────────────────────────────────────
    with tabs[6]:
        st.markdown("#### 🌐 DHCP")
        dhcp_tabs = st.tabs(["DHCP Servers", "DHCP Relay"])
        with dhcp_tabs[0]:
            rows = parser.get_dhcp_servers()
            if rows:
                st.dataframe(
                    pd.DataFrame(rows), use_container_width=True, hide_index=True
                )
                st.caption(f"Total: {len(rows)} DHCP server interfaces")
            else:
                st.info("No DHCP servers.")
        with dhcp_tabs[1]:
            _show(parser.get_dhcp_relays(), "No DHCP relays.", key="dhcp_relay")

    # ── DNS Proxy ─────────────────────────────────────────────
    with tabs[7]:
        st.markdown("#### 🔍 DNS Proxy")
        _show(parser.get_dns_proxies(), "No DNS proxy.", key="dns_proxy")

    # ── GlobalProtect ─────────────────────────────────────────
    with tabs[8]:
        st.markdown("#### 🔒 GlobalProtect")
        gp_tabs = st.tabs(
            ["Portals", "Gateways", "MDM", "Clientless Apps", "Clientless Groups"]
        )
        with gp_tabs[0]:
            _show(parser.get_gp_portals(), "No GP portals.", key="gp_portals")
        with gp_tabs[1]:
            _show(parser.get_gp_gateways(), "No GP gateways.", key="gp_gw")
        with gp_tabs[2]:
            _show(parser.get_gp_mdm(), "No MDM configured.", key="gp_mdm")
        with gp_tabs[3]:
            _show(parser.get_gp_clientless_apps(), "No clientless apps.", key="gp_apps")
        with gp_tabs[4]:
            _show(
                parser.get_gp_clientless_groups(),
                "No clientless groups.",
                key="gp_grps",
            )

    # ── QoS ───────────────────────────────────────────────────
    with tabs[9]:
        st.markdown("#### 📶 QoS")
        qos_tabs = st.tabs(["QoS Interfaces", "QoS Profiles"])
        with qos_tabs[0]:
            _show(parser.get_qos_interfaces(), "No QoS interfaces.", key="qos_intf")
        with qos_tabs[1]:
            profiles = parser.get_qos_profiles()
            if not profiles:
                st.info("No QoS profiles.")
            else:
                for prof in profiles:
                    with st.expander(f"**{prof['name']}**"):
                        if prof["classes"]:
                            df = pd.DataFrame(prof["classes"])

                            def hl_qos(row):
                                pri = str(row.get("Priority", "")).lower()
                                if pri == "real-time":
                                    return ["background-color:#fde8e8"] * len(row)
                                if pri == "high":
                                    return ["background-color:#fef3e2"] * len(row)
                                if pri == "medium":
                                    return ["background-color:#e8f8f0"] * len(row)
                                return [""] * len(row)

                            st.dataframe(
                                df.style.apply(hl_qos, axis=1),
                                use_container_width=True,
                                hide_index=True,
                            )
                        else:
                            st.info("No classes.")
                st.caption(f"Total: {len(profiles)} profiles")

    # ── Network Profiles ──────────────────────────────────────
    with tabs[10]:
        st.markdown("#### ⚙️ Network Profiles")
        np_tabs = st.tabs(
            [
                "GP-IPSec Crypto",
                "IKE Gateways",
                "IKE Crypto",
                "IPSec Crypto",
                "Monitor",
                "Interface Mgmt",
                "Zone Protection",
                "LLDP Profiles",
                "BFD Profiles",
            ]
        )
        with np_tabs[0]:
            _show(
                parser.get_gp_ipsec_crypto(),
                "No GP IPSec crypto profiles.",
                key="gp_ipsec_c",
            )
        with np_tabs[1]:
            rows = parser.get_ike_gateways()
            if rows:
                st.dataframe(
                    pd.DataFrame(rows), use_container_width=True, hide_index=True
                )
                st.caption(f"Total: {len(rows)} IKE gateways")
            else:
                st.info("No IKE gateways.")
        with np_tabs[2]:
            _show(
                parser.get_ike_crypto_profiles(), "No IKE crypto profiles.", key="ike_c"
            )
        with np_tabs[3]:
            _show(
                parser.get_ipsec_crypto_profiles(),
                "No IPSec crypto profiles.",
                key="ipsec_c",
            )
        with np_tabs[4]:
            _show(parser.get_monitor_profiles(), "No monitor profiles.", key="mon_p")
        with np_tabs[5]:
            rows = parser.get_intf_mgmt_profiles()
            if rows:
                st.dataframe(
                    pd.DataFrame(rows), use_container_width=True, hide_index=True
                )
                st.caption(f"Total: {len(rows)} interface management profiles")
            else:
                st.info("No interface management profiles.")
        with np_tabs[6]:
            _show(
                parser.get_zone_protection_profiles(),
                "No zone protection profiles.",
                key="zp_p",
            )
        with np_tabs[7]:
            _show(parser.get_lldp_profiles(), "No LLDP profiles.", key="lldp_p")
        with np_tabs[8]:
            _show(parser.get_bfd_profiles(), "No BFD profiles.", key="bfd_p")

    # ── SD-WAN Interface Profiles ─────────────────────────────
    with tabs[11]:
        st.markdown("#### 📡 SD-WAN Interface Profiles")
        rows = parser.get_sdwan_interface_profiles()
        if rows:
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            st.caption(f"Total: {len(rows)} SD-WAN profiles")
        else:
            st.info("No SD-WAN interface profiles.")


# Palo Alto Network views – full overhaul with all enhancements.
