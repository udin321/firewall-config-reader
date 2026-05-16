"""views/network_view.py — FortiGate Network tab. Every table is searchable + exportable."""

import streamlit as st
import pandas as pd
from views.table_utils import st_table


def _show(
    rows, key, empty="Not configured.", export_filename=None, style_fn=None, caption=""
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


def render_network(parser):
    st.subheader("Network Configuration")

    (
        tab_ipam,
        tab_ext,
        tab_sdwan,
        tab_static,
        tab_policy,
        tab_rip,
        tab_ospf,
        tab_bgp,
        tab_obj,
        tab_mcast,
    ) = st.tabs(
        [
            "IPAM",
            "FortiExtender",
            "SD-WAN",
            "Static Routes",
            "Policy Routes",
            "RIP",
            "OSPF",
            "BGP",
            "Routing Objects",
            "Multicast",
        ]
    )

    # ── IPAM ──────────────────────────────────────────────────
    with tab_ipam:
        st.markdown("#### IP Address Management")
        _show(
            parser.parse_ipam(),
            key="fg_ipam",
            empty="No IPAM configuration found.",
            export_filename="fg_ipam.csv",
        )

    # ── FortiExtender ──────────────────────────────────────────
    with tab_ext:
        st.markdown("#### FortiExtender Devices")
        _show(
            parser.parse_fortiextender(),
            key="fg_fortiext",
            empty="No FortiExtender configuration found.",
            export_filename="fg_fortiextender.csv",
        )

    # ── SD-WAN ────────────────────────────────────────────────
    with tab_sdwan:
        sdwan = parser.parse_sdwan()
        if not sdwan:
            st.info("No SD-WAN configuration found.")
        else:
            status_color = "🟢" if sdwan.get("status", "").lower() == "enable" else "🔴"
            st.markdown(f"**SD-WAN Status:** {status_color} {sdwan.get('status','-')}")
            st.divider()

            st.markdown("##### SD-WAN Zones / Members")
            zones = sdwan.get("zones", [])
            members_raw = sdwan.get("members", [])
            zone_rows = []
            for z in zones:
                zname = z["Zone Name"]
                zmembers = [m for m in members_raw if m["Zone"] == zname]
                if zmembers:
                    for m in zmembers:
                        zone_rows.append(
                            {
                                "Zone": zname,
                                "Seq": m["Seq"],
                                "Interface": m["Interface"],
                                "Gateway": m["Gateway"],
                                "Cost": m["Cost"],
                                "Priority": m["Priority"],
                                "Status": m["Status"],
                            }
                        )
                else:
                    zone_rows.append(
                        {
                            "Zone": zname,
                            "Seq": "-",
                            "Interface": "(no members)",
                            "Gateway": "-",
                            "Cost": "-",
                            "Priority": "-",
                            "Status": "-",
                        }
                    )
            _show(
                zone_rows,
                key="fg_sdwan_zones",
                empty="No SD-WAN zones.",
                export_filename="fg_sdwan_zones.csv",
            )

            st.divider()
            st.markdown("##### SD-WAN Rules")
            services = sdwan.get("services", [])

            def _hl_svc(row):
                if str(row.get("Status", "")).lower() == "disable":
                    return ["background-color:#fdecea;color:#999"] * len(row)
                return [""] * len(row)

            _show(
                services,
                key="fg_sdwan_rules",
                style_fn=_hl_svc,
                empty="No SD-WAN rules.",
                export_filename="fg_sdwan_rules.csv",
            )

            st.divider()
            st.markdown("##### Performance SLA")
            _show(
                sdwan.get("health_checks", []),
                key="fg_sdwan_sla",
                empty="No health checks configured.",
                export_filename="fg_sdwan_sla.csv",
            )

    # ── Static Routes ─────────────────────────────────────────
    with tab_static:
        st.markdown("#### Static Routes")
        rows = parser.parse_static_routes()

        def _hl_static(row):
            if str(row.get("Status", "")).lower() == "disable":
                return [
                    "background-color:#fdecea;color:#999;text-decoration:line-through"
                ] * len(row)
            return [""] * len(row)

        en = len([r for r in rows if str(r.get("Status", "")).lower() != "disable"])
        dis = len(rows) - en
        _show(
            rows,
            key="fg_static_routes",
            style_fn=_hl_static,
            empty="No static routes configured.",
            export_filename="fg_static_routes.csv",
            caption=f"✅ {en} active · 🔴 {dis} disabled",
        )

    # ── Policy Routes ─────────────────────────────────────────
    with tab_policy:
        st.markdown("#### Policy Routes")
        rows = parser.parse_policy_routes()

        def _hl_pr(row):
            if str(row.get("Status", "")).lower() == "disable":
                return [
                    "background-color:#fdecea;color:#999;text-decoration:line-through"
                ] * len(row)
            return [""] * len(row)

        en = len([r for r in rows if str(r.get("Status", "")).lower() != "disable"])
        dis = len(rows) - en
        _show(
            rows,
            key="fg_policy_routes",
            style_fn=_hl_pr,
            empty="No policy routes configured.",
            export_filename="fg_policy_routes.csv",
            caption=f"✅ {en} active · 🔴 {dis} disabled",
        )

    # ── RIP ───────────────────────────────────────────────────
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
            _show(
                rip.get("interfaces", []),
                key="fg_rip_ifaces",
                empty="No RIP interfaces.",
                export_filename="fg_rip_interfaces.csv",
            )

    # ── OSPF ──────────────────────────────────────────────────
    with tab_ospf:
        ospf = parser.parse_ospf()
        if not ospf:
            st.info("No OSPF configuration found.")
        else:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Router ID", ospf.get("router_id", "-"))
            c2.metric("ABR Type", ospf.get("abr_type", "-"))
            c3.metric("Auto Cost Ref", ospf.get("auto_cost", "-"))
            c4.metric("Default Originate", ospf.get("default_info", "-"))
            st.divider()
            st.markdown("##### Areas")
            _show(
                ospf.get("areas", []),
                key="fg_ospf_areas",
                empty="No OSPF areas.",
                export_filename="fg_ospf_areas.csv",
            )
            st.markdown("##### OSPF Interfaces")
            _show(
                ospf.get("interfaces", []),
                key="fg_ospf_ifaces",
                empty="No OSPF interfaces.",
                export_filename="fg_ospf_interfaces.csv",
            )
            st.markdown("##### Networks")
            _show(
                ospf.get("networks", []),
                key="fg_ospf_nets",
                empty="No OSPF networks.",
                export_filename="fg_ospf_networks.csv",
            )

    # ── BGP ───────────────────────────────────────────────────
    with tab_bgp:
        bgp = parser.parse_bgp()
        if not bgp:
            st.info("No BGP configuration found.")
        else:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Local AS", bgp.get("local_as", "-"))
            c2.metric("Router ID", bgp.get("router_id", "-"))
            c3.metric("Keepalive", f"{bgp.get('keepalive','-')}s")
            c4.metric("Hold Time", f"{bgp.get('holdtime','-')}s")
            st.divider()
            st.markdown("##### Neighbors")
            _show(
                bgp.get("neighbors", []),
                key="fg_bgp_nbrs",
                empty="No BGP neighbors.",
                export_filename="fg_bgp_neighbors.csv",
            )
            st.markdown("##### Advertised Networks")
            _show(
                bgp.get("networks", []),
                key="fg_bgp_nets",
                empty="No BGP networks.",
                export_filename="fg_bgp_networks.csv",
            )

    # ── Routing Objects ───────────────────────────────────────
    with tab_obj:
        obj = parser.parse_routing_objects()
        st.markdown("##### Prefix Lists")
        _show(
            obj.get("prefix_lists", []),
            key="fg_prefix_lists",
            empty="No prefix lists.",
            export_filename="fg_prefix_lists.csv",
        )
        st.markdown("##### Route Maps")
        _show(
            obj.get("route_maps", []),
            key="fg_route_maps",
            empty="No route maps.",
            export_filename="fg_route_maps.csv",
        )
        st.markdown("##### AS Path Lists")
        _show(
            obj.get("aspath_lists", []),
            key="fg_aspath",
            empty="No AS path lists.",
            export_filename="fg_aspath_lists.csv",
        )

    # ── Multicast ─────────────────────────────────────────────
    with tab_mcast:
        mcast = parser.parse_multicast()
        if not mcast:
            st.info("No Multicast configuration found.")
        else:
            ok = mcast.get("enabled", "").lower() == "enable"
            st.markdown(
                f"**Multicast Routing:** {'🟢' if ok else '🔴'} {mcast.get('enabled','-')}"
            )
            st.divider()
            st.markdown("##### PIM Interfaces")
            _show(
                mcast.get("interfaces", []),
                key="fg_mcast_ifaces",
                empty="No multicast interfaces.",
                export_filename="fg_multicast_interfaces.csv",
            )
            pim_sm = mcast.get("pim_sm", {})
            if pim_sm:
                st.markdown("##### PIM-SM Rendezvous Points")
                if pim_sm.get("register_suppression", "-") != "-":
                    st.caption(
                        f"Register Suppression Timer: {pim_sm['register_suppression']}s"
                    )
                _show(
                    pim_sm.get("rp_list", []),
                    key="fg_pim_rp",
                    empty="No RP configured.",
                    export_filename="fg_pim_rp.csv",
                )
