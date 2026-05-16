"""Palo Alto — Network tab. Every table: search + column filter + CSV via st_table."""

import streamlit as st
import pandas as pd
from parsers.palo_network import PaloNetworkParser
from views.table_utils import st_table


def _show(
    rows,
    key: str,
    empty="Not configured.",
    export_filename=None,
    style_fn=None,
    caption="",
):
    if not rows:
        st.info(empty)
        return
    st_table(
        rows,
        key=key,
        style_fn=style_fn,
        caption=caption,
        export_filename=export_filename or f"{key}.csv",
    )


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

            def _hl_eth(row):
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

            _show(
                rows,
                key="pa_eth_ifaces",
                empty="No ethernet/aggregate interfaces.",
                style_fn=_hl_eth,
                export_filename="pa_ethernet_interfaces.csv",
            )

        with intf_tabs[1]:
            _show(
                parser.get_vlan_interfaces(),
                key="pa_vlan_ifaces",
                empty="No VLAN interfaces.",
                export_filename="pa_vlan_interfaces.csv",
            )

        with intf_tabs[2]:
            _show(
                parser.get_loopback_interfaces(),
                key="pa_lo_ifaces",
                empty="No loopback interfaces.",
                export_filename="pa_loopback_interfaces.csv",
            )

        with intf_tabs[3]:
            _show(
                parser.get_tunnel_interfaces(),
                key="pa_tun_ifaces",
                empty="No tunnel interfaces.",
                export_filename="pa_tunnel_interfaces.csv",
            )

        with intf_tabs[4]:
            _show(
                parser.get_sdwan_interfaces(),
                key="pa_sdwan_ifaces",
                empty="No SD-WAN interfaces.",
                export_filename="pa_sdwan_interfaces.csv",
            )

    # ── Zones ─────────────────────────────────────────────────
    with tabs[1]:
        st.markdown("#### 🗺️ Zones")
        rows = parser.get_zones()
        _show(
            rows,
            key="pa_zones",
            empty="No zones configured.",
            export_filename="pa_zones.csv",
            caption=f"{len(rows)} zones" if rows else "",
        )

    # ── VLANs ─────────────────────────────────────────────────
    with tabs[2]:
        st.markdown("#### 🔗 VLANs")
        _show(
            parser.get_vlans(),
            key="pa_vlans",
            empty="No VLAN objects.",
            export_filename="pa_vlans.csv",
        )

    # ── Virtual Wires ─────────────────────────────────────────
    with tabs[3]:
        st.markdown("#### ↔️ Virtual Wires")
        _show(
            parser.get_virtual_wires(),
            key="pa_vwires",
            empty="No virtual wires.",
            export_filename="pa_virtual_wires.csv",
        )

    # ── Virtual Router ────────────────────────────────────────
    with tabs[4]:
        st.markdown("#### 🔀 Virtual Router")
        vrs = parser.get_virtual_routers()
        if not vrs:
            st.info("No virtual routers.")
        else:
            df_vr = pd.DataFrame(
                [{k: v for k, v in r.items() if k != "_vr_el"} for r in vrs]
            )
            st_table(
                df_vr,
                key="pa_vr_list",
                export_filename="pa_virtual_routers.csv",
                caption=f"{len(vrs)} virtual routers",
            )
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
                                st_table(
                                    ad_rows,
                                    key=f"pa_vr_{detail['name']}_ad",
                                    export_filename=f"pa_vr_{detail['name']}_ad.csv",
                                )
                        ecmp = detail["ecmp"]
                        enabled = ecmp.get("enabled") == "yes"
                        st.markdown(
                            f"**ECMP:** {'✅ Enabled' if enabled else '❌ Disabled'}"
                        )
                        if enabled:
                            c1, c2, c3 = st.columns(3)
                            c1.metric("Method", ecmp.get("method", "-"))
                            c2.metric(
                                "Symmetric Return", ecmp.get("symmetric_return", "-")
                            )
                            c3.metric("Strict Source", ecmp.get("strict_source", "-"))
                    with vr_sub[1]:
                        sr = detail.get("static_v4", [])

                        def _hl_sr(row):
                            return (
                                ["background-color:#e8f8f0"] * len(row)
                                if row.get("Path Mon") == "yes"
                                else [""] * len(row)
                            )

                        _show(
                            sr,
                            key=f"pa_vr_{detail['name']}_routes",
                            style_fn=_hl_sr,
                            empty="No static routes.",
                            export_filename=f"pa_vr_{detail['name']}_static_routes.csv",
                            caption=f"{len(sr)} IPv4 routes",
                        )
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
            _show(
                parser.get_ipsec_tunnels(),
                key="pa_ipsec",
                empty="No IPSec tunnels.",
                export_filename="pa_ipsec_tunnels.csv",
            )
        with ipsec_tabs[1]:
            _show(
                parser.get_gre_tunnels(),
                key="pa_gre",
                empty="No GRE tunnels.",
                export_filename="pa_gre_tunnels.csv",
            )

    # ── DHCP ──────────────────────────────────────────────────
    with tabs[6]:
        st.markdown("#### 🌐 DHCP")
        dhcp_tabs = st.tabs(["DHCP Servers", "DHCP Relay"])
        with dhcp_tabs[0]:
            _show(
                parser.get_dhcp_servers(),
                key="pa_dhcp_srv",
                empty="No DHCP servers.",
                export_filename="pa_dhcp_servers.csv",
            )
        with dhcp_tabs[1]:
            _show(
                parser.get_dhcp_relays(),
                key="pa_dhcp_relay",
                empty="No DHCP relays.",
                export_filename="pa_dhcp_relays.csv",
            )

    # ── DNS Proxy ─────────────────────────────────────────────
    with tabs[7]:
        st.markdown("#### 🔍 DNS Proxy")
        _show(
            parser.get_dns_proxies(),
            key="pa_dns_proxy",
            empty="No DNS proxy.",
            export_filename="pa_dns_proxy.csv",
        )

    # ── GlobalProtect ─────────────────────────────────────────
    with tabs[8]:
        st.markdown("#### 🔒 GlobalProtect")
        gp_tabs = st.tabs(
            ["Portals", "Gateways", "MDM", "Clientless Apps", "Clientless Groups"]
        )
        with gp_tabs[0]:
            _show(
                parser.get_gp_portals(),
                key="pa_gp_portals",
                empty="No GP portals.",
                export_filename="pa_gp_portals.csv",
            )
        with gp_tabs[1]:
            _show(
                parser.get_gp_gateways(),
                key="pa_gp_gw",
                empty="No GP gateways.",
                export_filename="pa_gp_gateways.csv",
            )
        with gp_tabs[2]:
            _show(
                parser.get_gp_mdm(),
                key="pa_gp_mdm",
                empty="No MDM configured.",
                export_filename="pa_gp_mdm.csv",
            )
        with gp_tabs[3]:
            _show(
                parser.get_gp_clientless_apps(),
                key="pa_gp_apps",
                empty="No clientless apps.",
                export_filename="pa_gp_clientless_apps.csv",
            )
        with gp_tabs[4]:
            _show(
                parser.get_gp_clientless_groups(),
                key="pa_gp_grps",
                empty="No clientless groups.",
                export_filename="pa_gp_clientless_groups.csv",
            )

    # ── QoS ───────────────────────────────────────────────────
    with tabs[9]:
        st.markdown("#### 📶 QoS")
        qos_tabs = st.tabs(["QoS Interfaces", "QoS Profiles"])
        with qos_tabs[0]:
            _show(
                parser.get_qos_interfaces(),
                key="pa_qos_intf",
                empty="No QoS interfaces.",
                export_filename="pa_qos_interfaces.csv",
            )
        with qos_tabs[1]:
            profiles = parser.get_qos_profiles()
            if not profiles:
                st.info("No QoS profiles.")
            else:
                for prof in profiles:
                    with st.expander(f"**{prof['name']}**"):

                        def _hl_qos(row):
                            pri = str(row.get("Priority", "")).lower()
                            if pri == "real-time":
                                return ["background-color:#fde8e8"] * len(row)
                            if pri == "high":
                                return ["background-color:#fef3e2"] * len(row)
                            if pri == "medium":
                                return ["background-color:#e8f8f0"] * len(row)
                            return [""] * len(row)

                        if prof["classes"]:
                            st_table(
                                prof["classes"],
                                key=f"pa_qos_{prof['name']}",
                                style_fn=_hl_qos,
                                export_filename=f"pa_qos_{prof['name']}.csv",
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
        for subtab, meth, key, fname, empty in [
            (
                np_tabs[0],
                "get_gp_ipsec_crypto",
                "pa_gp_ipsec_c",
                "pa_gp_ipsec_crypto.csv",
                "No GP IPSec crypto profiles.",
            ),
            (
                np_tabs[1],
                "get_ike_gateways",
                "pa_ike_gw",
                "pa_ike_gateways.csv",
                "No IKE gateways.",
            ),
            (
                np_tabs[2],
                "get_ike_crypto_profiles",
                "pa_ike_c",
                "pa_ike_crypto.csv",
                "No IKE crypto profiles.",
            ),
            (
                np_tabs[3],
                "get_ipsec_crypto_profiles",
                "pa_ipsec_c",
                "pa_ipsec_crypto.csv",
                "No IPSec crypto profiles.",
            ),
            (
                np_tabs[4],
                "get_monitor_profiles",
                "pa_mon_p",
                "pa_monitor_profiles.csv",
                "No monitor profiles.",
            ),
            (
                np_tabs[5],
                "get_intf_mgmt_profiles",
                "pa_intf_mgmt",
                "pa_intf_mgmt_profiles.csv",
                "No interface management profiles.",
            ),
            (
                np_tabs[6],
                "get_zone_protection_profiles",
                "pa_zp_p",
                "pa_zone_protection_profiles.csv",
                "No zone protection profiles.",
            ),
            (
                np_tabs[7],
                "get_lldp_profiles",
                "pa_lldp_p",
                "pa_lldp_profiles.csv",
                "No LLDP profiles.",
            ),
            (
                np_tabs[8],
                "get_bfd_profiles",
                "pa_bfd_p",
                "pa_bfd_profiles.csv",
                "No BFD profiles.",
            ),
        ]:
            with subtab:
                _show(
                    getattr(parser, meth)(), key=key, empty=empty, export_filename=fname
                )

    # ── SD-WAN Interface Profiles ─────────────────────────────
    with tabs[11]:
        st.markdown("#### 📡 SD-WAN Interface Profiles")
        _show(
            parser.get_sdwan_interface_profiles(),
            key="pa_sdwan_profs",
            empty="No SD-WAN interface profiles.",
            export_filename="pa_sdwan_interface_profiles.csv",
        )
