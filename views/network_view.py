import streamlit as st
import pandas as pd


def _show_table(rows: list, empty_msg: str = "Not configured"):
    if not rows:
        st.info(empty_msg)
        return
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def render_network(parser):
    st.subheader("Network Configuration")

    (
        tab_ipam, tab_ext, tab_sdwan,
        tab_static, tab_policy,
        tab_rip, tab_ospf, tab_bgp,
        tab_obj, tab_mcast
    ) = st.tabs([
        "IPAM", "FortiExtender", "SD-WAN",
        "Static Routes", "Policy Routes",
        "RIP", "OSPF", "BGP",
        "Routing Objects", "Multicast"
    ])

    with tab_ipam:
        st.markdown("#### IP Address Management")
        _show_table(parser.parse_ipam(), "No IPAM configuration found.")

    with tab_ext:
        st.markdown("#### FortiExtender Devices")
        _show_table(parser.parse_fortiextender(), "No FortiExtender configuration found.")

    with tab_sdwan:
        sdwan = parser.parse_sdwan()
        if not sdwan:
            st.info("No SD-WAN configuration found.")
        else:
            status_color = "🟢" if sdwan.get("status", "").lower() == "enable" else "🔴"
            st.markdown(f"**SD-WAN Status:** {status_color} {sdwan.get('status', '-')}")
            st.divider()
            st.markdown("##### SD-WAN Zones")
            zones = sdwan.get("zones", [])
            members_raw = sdwan.get("members", [])
            if not zones:
                st.info("No zones configured.")
            else:
                zone_rows = []
                for z in zones:
                    zone_name = z["Zone Name"]
                    zone_members = [m for m in members_raw if m["Zone"] == zone_name]
                    if zone_members:
                        for m in zone_members:
                            zone_rows.append({
                                "Zone": zone_name, "Seq": m["Seq"],
                                "Interface": m["Interface"], "Gateway": m["Gateway"],
                                "Cost": m["Cost"], "Priority": m["Priority"], "Status": m["Status"],
                            })
                    else:
                        zone_rows.append({
                            "Zone": zone_name, "Seq": "-", "Interface": "(no members)",
                            "Gateway": "-", "Cost": "-", "Priority": "-", "Status": "-",
                        })
                _show_table(zone_rows)
            st.divider()
            st.markdown("##### SD-WAN Rules")
            services = sdwan.get("services", [])
            if not services:
                st.info("No SD-WAN rules configured.")
            else:
                df_svc = pd.DataFrame(services)
                def highlight_svc(row):
                    if str(row.get("Status", "")).lower() == "disable":
                        return ["background-color:#fdecea;color:#999"] * len(row)
                    return [""] * len(row)
                st.dataframe(df_svc.style.apply(highlight_svc, axis=1), use_container_width=True, hide_index=True)
            st.divider()
            st.markdown("##### Performance SLA")
            _show_table(sdwan.get("health_checks", []), "No health checks configured.")

    with tab_static:
        st.markdown("#### Static Routes")
        rows = parser.parse_static_routes()
        if rows:
            df = pd.DataFrame(rows)
            def highlight_status(row):
                if str(row.get("Status", "")).lower() == "disable":
                    return ["background-color:#fdecea;color:#999;text-decoration:line-through"] * len(row)
                return [""] * len(row)
            st.dataframe(df.style.apply(highlight_status, axis=1), use_container_width=True, hide_index=True)
            enabled  = len([r for r in rows if str(r.get("Status","")).lower() != "disable"])
            disabled = len(rows) - enabled
            st.caption(f"Total: {len(rows)} | ✅ {enabled} active | 🔴 {disabled} disabled")
        else:
            st.info("No static routes configured.")

    with tab_policy:
        st.markdown("#### Policy Routes")
        rows = parser.parse_policy_routes()
        if not rows:
            st.info("No policy routes configured.")
        else:
            df = pd.DataFrame(rows)
            def highlight_pr(row):
                if str(row.get("Status", "")).lower() == "disable":
                    return ["background-color:#fdecea;color:#999;text-decoration:line-through"] * len(row)
                return [""] * len(row)
            st.dataframe(df.style.apply(highlight_pr, axis=1), use_container_width=True, hide_index=True)
            enabled  = len([r for r in rows if str(r.get("Status","")).lower() != "disable"])
            disabled = len(rows) - enabled
            st.caption(f"Total: {len(rows)} | ✅ {enabled} active | 🔴 {disabled} disabled")

    with tab_rip:
        rip = parser.parse_rip()
        if not rip:
            st.info("No RIP configuration found.")
        else:
            c1, c2, c3 = st.columns(3)
            c1.metric("Version", rip.get("version", "-"))
            c2.metric("Default Metric", rip.get("default_metric", "-"))
            c3.metric("Originate Default", rip.get("default_info", "-"))
            st.markdown("##### Networks")
            if rip.get("networks"):
                for net in rip["networks"]:
                    st.code(net, language=None)
            else:
                st.info("No networks configured.")
            st.markdown("##### Interfaces")
            _show_table(rip.get("interfaces", []), "No RIP interfaces configured.")

    with tab_ospf:
        ospf = parser.parse_ospf()
        if not ospf:
            st.info("No OSPF configuration found.")
        else:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Router ID",         ospf.get("router_id", "-"))
            c2.metric("ABR Type",          ospf.get("abr_type", "-"))
            c3.metric("Auto Cost Ref",     ospf.get("auto_cost", "-"))
            c4.metric("Default Originate", ospf.get("default_info", "-"))
            st.divider()
            st.markdown("##### Areas")
            _show_table(ospf.get("areas", []), "No OSPF areas configured.")
            st.markdown("##### OSPF Interfaces")
            _show_table(ospf.get("interfaces", []), "No OSPF interfaces configured.")
            st.markdown("##### Networks")
            _show_table(ospf.get("networks", []), "No OSPF networks configured.")

    with tab_bgp:
        bgp = parser.parse_bgp()
        if not bgp:
            st.info("No BGP configuration found.")
        else:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Local AS",  bgp.get("local_as", "-"))
            c2.metric("Router ID", bgp.get("router_id", "-"))
            c3.metric("Keepalive", f"{bgp.get('keepalive', '-')}s")
            c4.metric("Hold Time", f"{bgp.get('holdtime', '-')}s")
            st.divider()
            st.markdown("##### Neighbors")
            _show_table(bgp.get("neighbors", []), "No BGP neighbors configured.")
            st.markdown("##### Advertised Networks")
            _show_table(bgp.get("networks", []), "No BGP networks configured.")

    with tab_obj:
        obj = parser.parse_routing_objects()
        st.markdown("##### Prefix Lists")
        _show_table(obj.get("prefix_lists", []), "No prefix lists configured.")
        st.markdown("##### Route Maps")
        _show_table(obj.get("route_maps", []), "No route maps configured.")
        st.markdown("##### AS Path Lists")
        _show_table(obj.get("aspath_lists", []), "No AS path lists configured.")

    with tab_mcast:
        mcast = parser.parse_multicast()
        if not mcast:
            st.info("No Multicast configuration found.")
        else:
            status_color = "🟢" if mcast.get("enabled", "").lower() == "enable" else "🔴"
            st.markdown(f"**Multicast Routing:** {status_color} {mcast.get('enabled', '-')}")
            st.divider()
            st.markdown("##### PIM Interfaces")
            _show_table(mcast.get("interfaces", []), "No multicast interfaces configured.")
            pim_sm = mcast.get("pim_sm", {})
            if pim_sm:
                st.markdown("##### PIM-SM Rendezvous Points")
                if pim_sm.get("register_suppression") != "-":
                    st.caption(f"Register Suppression Timer: {pim_sm['register_suppression']}s")
                _show_table(pim_sm.get("rp_list", []), "No RP configured.")
