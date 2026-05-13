import streamlit as st
import pandas as pd


def _show_table(rows, empty_msg="Not configured"):
    if not rows:
        st.info(empty_msg)
        return
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _metric(label, value):
    st.markdown(f"**{label}:** {value}")


def _ipsec_detail(phase1, phase2_list):
    """Show full detail of a single IPSec tunnel."""
    p = phase1

    st.markdown("### Network")
    c1, c2, c3 = st.columns(3)
    c1.metric("IP Version",      f"IPv{p.get('ip_version', '4')}")
    c2.metric("Remote Gateway",  p.get("remote_gw", "-"))
    c3.metric("Interface",       p.get("interface", "-"))

    c4, c5, c6 = st.columns(3)
    c4.metric("Local Gateway",   p.get("local_gw", "Not specified"))
    c5.metric("Mode Config",     p.get("mode_cfg", "-").capitalize())
    c6.metric("NAT Traversal",   p.get("nattraversal", "-").capitalize())

    c7, c8, c9 = st.columns(3)
    c7.metric("Dead Peer Detection", p.get("dpd", "-").replace("-", " ").title())
    c8.metric("DPD Retry Count",     p.get("dpd_retrycount", "-"))
    c9.metric("DPD Retry Interval",  f"{p.get('dpd_retryinterval', '-')}s")

    c10, c11, c12 = st.columns(3)
    c10.metric("FEC Egress",       p.get("fec_egress", "-").capitalize())
    c11.metric("FEC Ingress",      p.get("fec_ingress", "-").capitalize())
    c12.metric("Add Route",        p.get("add_route", "-").capitalize())

    c13, c14, c15 = st.columns(3)
    c13.metric("Auto Disc Sender",   p.get("auto_disc_sender", "-").capitalize())
    c14.metric("Auto Disc Receiver", p.get("auto_disc_receiver", "-").capitalize())
    c15.metric("Exchange Intf IP",   p.get("exchange_intf_ip", "-").capitalize())

    c16, c17 = st.columns(2)
    c16.metric("Device Creation", p.get("dev_creation", "-").capitalize())
    c17.metric("Net Device",      p.get("net_device", "-").capitalize())

    st.divider()
    st.markdown("### Authentication")
    c1, c2, c3 = st.columns(3)
    c1.metric("Method",      p.get("authmethod", "psk").upper().replace("PSK", "Pre-shared Key").replace("SIGNATURE", "Signature"))
    c2.metric("IKE Version", f"IKEv{p.get('ike_version', '1')}")
    c3.metric("Mode",        p.get("mode", "main").replace("main", "Main (ID Protection)").replace("aggressive", "Aggressive").title())

    st.divider()
    st.markdown("### Phase 1 Proposal")
    proposals = p.get("proposal", "-").split()
    if proposals and proposals[0] != "-":
        prop_rows = []
        for prop in proposals:
            parts = prop.split("-")
            enc  = parts[0].upper() if len(parts) > 0 else "-"
            auth = parts[1].upper() if len(parts) > 1 else "-"
            prop_rows.append({"Encryption": enc, "Authentication": auth})
        st.dataframe(pd.DataFrame(prop_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No proposal configured.")

    c1, c2, c3 = st.columns(3)
    c1.metric("DH Group",       p.get("dhgrp", "-"))
    c2.metric("Key Lifetime",   f"{p.get('keylifetime', '86400')}s")
    c3.metric("Local ID",       p.get("localid", "Not specified"))

    if p.get("xauthtype", "disable") != "disable":
        st.divider()
        st.markdown("### XAuth")
        st.metric("XAuth Type", p.get("xauthtype", "-").capitalize())

    # Phase 2 selectors for this tunnel
    tunnel_p2 = [p2 for p2 in phase2_list if p2.get("phase1name") == p.get("name")]
    if tunnel_p2:
        st.divider()
        st.markdown("### Phase 2 Selectors")
        for p2 in tunnel_p2:
            with st.expander(f"Selector: {p2.get('name', '-')}", expanded=len(tunnel_p2) == 1):
                if p2.get("comments", "-") != "-":
                    st.markdown(f"**Comment:** {p2.get('comments', '-')}")

                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("**Local Address**")
                    src_type = p2.get("src_addr_type", "subnet")
                    src_val  = p2.get("src_name", "-") if src_type == "name" else p2.get("src_subnet", "-")
                    st.code(f"Type: {src_type}\nValue: {src_val}", language=None)
                with c2:
                    st.markdown("**Remote Address**")
                    dst_type = p2.get("dst_addr_type", "subnet")
                    dst_val  = p2.get("dst_name", "-") if dst_type == "name" else p2.get("dst_subnet", "-")
                    st.code(f"Type: {dst_type}\nValue: {dst_val}", language=None)

                proposals = p2.get("proposal", "-").split()
                prop_rows = []
                for prop in proposals:
                    parts = prop.split("-")
                    prop_rows.append({
                        "Encryption":     parts[0].upper() if len(parts) > 0 else "-",
                        "Authentication": parts[1].upper() if len(parts) > 1 else "-",
                    })
                if prop_rows:
                    st.dataframe(pd.DataFrame(prop_rows), use_container_width=True, hide_index=True)

                c1, c2, c3, c4 = st.columns(4)
                c1.metric("DH Group",      p2.get("dhgrp", "-"))
                c2.metric("Key Lifetime",  f"{p2.get('keylifeseconds', '43200')}s")
                c3.metric("Replay",        p2.get("replay", "-").capitalize())
                c4.metric("PFS",           p2.get("pfs", "-").capitalize())

                c5, c6, c7, c8 = st.columns(4)
                c5.metric("Auto Negotiate", p2.get("auto_negotiate", "-").capitalize())
                c6.metric("Keepalive",      p2.get("keepalive", "-").capitalize())
                c7.metric("Local Port",     p2.get("src_port", "0"))
                c8.metric("Remote Port",    p2.get("dst_port", "0"))

                if p2.get("protocol", "0") != "0":
                    st.metric("Protocol", p2.get("protocol", "0"))


def _ssl_portal_detail(portal):
    p = portal
    c1, c2, c3 = st.columns(3)
    c1.metric("Tunnel Mode",    p.get("tunnel_mode", "-"))
    c2.metric("Web Mode",       p.get("web_mode", "-"))
    c3.metric("One User Limit", p.get("one_user_limit", "-"))

    st.markdown(f"**Split Tunneling:** {p.get('split_tunneling', '-')}")
    st.markdown(f"**IP Pools:** {p.get('ip_pools', '-')}")

    st.divider()
    st.markdown("#### Tunnel Mode Client Options")
    c1, c2, c3 = st.columns(3)
    c1.metric("Save Password",  p.get("save_password", "-"))
    c2.metric("Auto Connect",   p.get("auto_connect", "-"))
    c3.metric("Keep Alive",     p.get("keep_alive", "-"))

    c4, c5 = st.columns(2)
    c4.metric("DNS Split Tunneling", p.get("dns_split", "-"))
    c5.metric("Host Check",          p.get("host_check", "-").title())

    st.divider()
    st.markdown("#### Web Mode Settings")
    c1, c2 = st.columns(2)
    c1.metric("Theme",          p.get("theme", "Default"))
    c2.metric("Portal Message", p.get("portal_msg", "-"))

    c3, c4, c5 = st.columns(3)
    c3.metric("Show Session Info", p.get("show_session_info", "-"))
    c4.metric("Show Launcher",     p.get("show_launcher", "-"))
    c5.metric("Show History",      p.get("show_history", "-"))

    c6, c7, c8 = st.columns(3)
    c6.metric("User Bookmarks", p.get("user_bookmarks", "-"))
    c7.metric("Rewrite IP/UI",  p.get("rewrite_ip", "-"))
    c8.metric("RDP/VNC Clipboard", p.get("clipboard", "-"))

    st.divider()
    st.markdown("#### FortiClient Download")
    c1, c2 = st.columns(2)
    c1.metric("FortiClient Download", p.get("forticlient_download", "-"))

    bookmarks = p.get("bookmarks", [])
    st.divider()
    st.markdown("#### Predefined Bookmarks")
    if bookmarks:
        st.dataframe(pd.DataFrame(bookmarks), use_container_width=True, hide_index=True)
    else:
        st.info("No predefined bookmarks configured.")


def render_vpn(parser):
    st.subheader("VPN Configuration")

    tab_ipsec, tab_conc, tab_portal, tab_ssl_settings, tab_ssl_clients = st.tabs([
        "IPSec Tunnels", "IPSec Concentrator",
        "SSL-VPN Portals", "SSL-VPN Settings", "SSL-VPN Clients"
    ])

    # ── IPSec Tunnels ─────────────────────────────────────────────────────────
    with tab_ipsec:
        st.markdown("#### IPSec Tunnels")
        phase1_list = parser.parse_ipsec_phase1()
        phase2_list = parser.parse_ipsec_phase2()

        if not phase1_list:
            st.info("No IPSec tunnels configured.")
        else:
            # Summary table
            summary = [{
                "Tunnel":             p["name"],
                "Interface Binding":  p["interface"],
                "Remote Gateway":     p["remote_gw"],
                "IKE Version":        f"IKEv{p['ike_version']}",
                "Status":             p["status"],
                "Comment":            p["comments"],
            } for p in phase1_list]

            df = pd.DataFrame(summary)
            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Status": st.column_config.TextColumn("Status"),
                    "Interface Binding": st.column_config.TextColumn("Interface Binding"),
                }
            )

            st.divider()
            st.markdown("#### Tunnel Details")
            tunnel_names = [p["name"] for p in phase1_list]
            selected = st.selectbox("Select tunnel to inspect", tunnel_names, key="ipsec_select")
            if selected:
                phase1 = next(p for p in phase1_list if p["name"] == selected)
                if phase1.get("comments", "-") != "-":
                    st.markdown(f"**Comment:** {phase1.get('comments', '-')}")
                _ipsec_detail(phase1, phase2_list)

    # ── IPSec Concentrator ────────────────────────────────────────────────────
    with tab_conc:
        st.markdown("#### IPSec Concentrator")
        _show_table(parser.parse_ipsec_concentrator(), "No IPSec concentrators configured.")

    # ── SSL-VPN Portals ───────────────────────────────────────────────────────
    with tab_portal:
        st.markdown("#### SSL-VPN Portals")
        portals = parser.parse_ssl_portals()
        if not portals:
            st.info("No SSL-VPN portals configured.")
        else:
            summary = [{
                "Name":        p["name"],
                "Tunnel Mode": p["tunnel_mode"],
                "Web Mode":    p["web_mode"],
                "IP Pools":    p["ip_pools"],
                "Split Tunneling": p["split_tunneling"],
            } for p in portals]
            st.dataframe(pd.DataFrame(summary), use_container_width=True, hide_index=True)

            st.divider()
            st.markdown("#### Portal Details")
            portal_names = [p["name"] for p in portals]
            selected = st.selectbox("Select portal to inspect", portal_names, key="portal_select")
            if selected:
                portal = next(p for p in portals if p["name"] == selected)
                st.markdown(f"##### {selected}")
                _ssl_portal_detail(portal)

    # ── SSL-VPN Settings ──────────────────────────────────────────────────────
    with tab_ssl_settings:
        st.markdown("#### SSL-VPN Settings")
        settings = parser.parse_ssl_settings()
        if not settings:
            st.info("No SSL-VPN settings configured.")
        else:
            st.markdown("##### Connection Settings")
            c1, c2, c3 = st.columns(3)
            c1.metric("Status",      settings.get("enabled", "-").capitalize())
            c2.metric("Port",        settings.get("port", "443"))
            c3.metric("Certificate", settings.get("servercert", "-"))

            c4, c5, c6 = st.columns(3)
            c4.metric("HTTP Redirect",    settings.get("http_redirect", "-").capitalize())
            c5.metric("Idle Timeout",     f"{settings.get('idle_timeout', '-')}s")
            c6.metric("Require Cert",     settings.get("require_cert", "-").capitalize())

            intf_list = settings.get("listen_interfaces", [])
            st.markdown(f"**Listen on Interface(s):** {', '.join(intf_list)}")
            st.markdown(f"**Restrict Access:** {settings.get('restrict_access', 'Allow Any')}")

            st.divider()
            st.markdown("##### Tunnel Mode Client Settings")
            c1, c2 = st.columns(2)
            c1.metric("DNS Server 1", settings.get("dns_server1", "Same as client"))
            c2.metric("DNS Server 2", settings.get("dns_server2", "-"))

            c3, c4 = st.columns(2)
            c3.metric("WINS Server 1",  settings.get("wins_server1", "-"))
            c4.metric("Default Portal", settings.get("default_portal", "-"))

            if settings.get("ip_range", "-") != "-":
                st.markdown(f"**Address Range:** {settings.get('ip_range', '-')}")

            st.divider()
            st.markdown("##### Authentication / Portal Mapping")
            auth_rules = settings.get("auth_rules", [])
            if auth_rules:
                st.dataframe(pd.DataFrame(auth_rules), use_container_width=True, hide_index=True)
            else:
                default_portal = settings.get("default_portal", "full-access")
                st.dataframe(pd.DataFrame([{
                    "Users/Groups": "All Other Users/Groups",
                    "Portal":       default_portal,
                }]), use_container_width=True, hide_index=True)

    # ── SSL-VPN Clients ───────────────────────────────────────────────────────
    with tab_ssl_clients:
        st.markdown("#### SSL-VPN Clients")
        _show_table(parser.parse_ssl_clients(), "No SSL-VPN client configurations found.")
