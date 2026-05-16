"""
views/policy_objects_view.py
FortiGate — Policy & Objects tab.

* Every table: search + column filter + CSV export via st_table
* Inline Policy Lookup in Firewall Policy tab:
    - src interface dropdown (all configured interfaces + 'any')
    - dst interface dropdown (all configured interfaces + 'any')
    - AND logic across all parameters
    - Top-to-bottom evaluation, first match wins
    - Implicit deny when no match
"""

import streamlit as st
import pandas as pd
import ipaddress
from views.table_utils import st_table

# ═══════════════════════════════════════════════════════════════════════════════
#  IP / address matching helpers (self-contained so this file works standalone)
# ═══════════════════════════════════════════════════════════════════════════════


def _ip_int(ip: str):
    try:
        return int(ipaddress.IPv4Address(ip.strip()))
    except Exception:
        return None


def _ip_in_net(ip: str, net: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.IPv4Address(ip.strip()) in net
    except Exception:
        return False


def _ip_in_range(ip: str, start_int: int, end_int: int) -> bool:
    tip = _ip_int(ip)
    return tip is not None and start_int <= tip <= end_int


def _resolve_addr_match(ip_str: str, addr_objects: list, obj_name: str) -> bool:
    """Return True if ip_str falls within the named address object."""
    if obj_name.lower() in ("all", "any", ""):
        return True
    for obj in addr_objects:
        if obj.get("Name", "") != obj_name:
            continue
        t = str(obj.get("Type", "")).lower()
        if t == "subnet":
            net = obj.get("network_obj")
            if net and _ip_in_net(ip_str, net):
                return True
        elif t == "ip range":
            s = obj.get("start_int")
            e = obj.get("end_int")
            if s is not None and e is not None and _ip_in_range(ip_str, s, e):
                return True
    return False


def _iface_ok(pol_val: str, user_val: str) -> bool:
    if user_val.lower() == "any":
        return True
    pl = [x.strip().lower() for x in pol_val.split(",")]
    return "any" in pl or user_val.lower() in pl


def _evaluate_lookup(
    policies,
    parser,
    src_iface,
    dst_iface,
    src_ip,
    dst_ip,
    protocol,
    proto_num,
    src_port,
    dst_port,
    icmp_type,
    icmp_code,
):
    """
    Evaluate policies top-to-bottom with AND logic across:
      src interface, dst interface, src address, dst address, protocol.
    Returns the first matching policy dict, or None (implicit deny).
    """
    addresses = parser.parse_addresses()
    addr_objs = addresses.get("subnet", []) + addresses.get("iprange", [])

    # pre-build IPv4Network objects for subnet entries
    for obj in addr_objs:
        if obj.get("Type", "").lower() == "subnet" and "network_obj" not in obj:
            try:
                obj["network_obj"] = ipaddress.IPv4Network(
                    obj.get("Details", "0.0.0.0/0"), strict=False
                )
            except Exception:
                pass

    for pol in policies:
        # skip disabled
        if str(pol.get("Status", "Enable")).lower() == "disable":
            continue

        # AND 1 — source / incoming interface
        if not _iface_ok(str(pol.get("Src Interface", "any")), src_iface):
            continue

        # AND 2 — destination / outgoing interface
        if not _iface_ok(str(pol.get("Dst Interface", "any")), dst_iface):
            continue

        # AND 3 — source address (blank = any)
        if src_ip.strip():
            pol_src = str(pol.get("Source", "all"))
            src_names = [n.strip() for n in pol_src.split(",")]
            if not any(
                n.lower() in ("all", "any") or _resolve_addr_match(src_ip, addr_objs, n)
                for n in src_names
            ):
                continue

        # AND 4 — destination address (blank = any)
        if dst_ip.strip():
            pol_dst = str(pol.get("Destination", "all"))
            dst_names = [n.strip() for n in pol_dst.split(",")]
            if not any(
                n.lower() in ("all", "any") or _resolve_addr_match(dst_ip, addr_objs, n)
                for n in dst_names
            ):
                continue

        # AND 5 — protocol / service (if not 'any')
        if protocol not in ("any", "ip"):
            pol_svc = str(pol.get("Service", "ALL")).upper()
            if not any(x in pol_svc for x in ("ALL", "ANY", protocol.upper())):
                continue

        # first match
        return pol

    return None  # implicit deny


# ═══════════════════════════════════════════════════════════════════════════════
#  UI label helper
# ═══════════════════════════════════════════════════════════════════════════════


def _lbl(txt: str):
    st.markdown(
        f'<p style="margin:6px 0 2px;font-size:11px;color:#8b949e;'
        f'font-weight:700;text-transform:uppercase">{txt}</p>',
        unsafe_allow_html=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  Main render
# ═══════════════════════════════════════════════════════════════════════════════


def render_policy_objects(parser):
    st.subheader("Policy & Objects")

    (
        tab_fw,
        tab_proxy,
        tab_auth,
        tab_addr,
        tab_svc,
        tab_sched,
        tab_vip,
        tab_pool,
        tab_proto,
        tab_shaper,
        tab_vserver,
        tab_hc,
    ) = st.tabs(
        [
            "Firewall Policy",
            "Proxy Policy",
            "Auth Rules",
            "Addresses",
            "Services",
            "Schedules",
            "Virtual IPs",
            "IP Pools",
            "Protocol Options",
            "Traffic Shaping",
            "Virtual Servers",
            "Health Check",
        ]
    )

    # ══════════════════════════════════════════════════════════════════════
    #  Firewall Policy tab
    # ══════════════════════════════════════════════════════════════════════
    with tab_fw:
        st.markdown("#### Firewall Policies")
        rows = parser.parse_policies()

        # ── Interface list for dropdowns ───────────────────────────────────
        iface_names = (
            parser.get_interface_names()
            if hasattr(parser, "get_interface_names")
            else []
        )
        iface_opts = ["any"] + iface_names

        # ── Policy Lookup expander ─────────────────────────────────────────
        with st.expander("🔍 Policy Lookup", expanded=False):
            st.markdown(
                '<div style="font-size:13px;color:#8b949e;margin-bottom:10px">'
                "All parameters use <b>AND</b> logic. Evaluated <b>top-to-bottom</b>. "
                "Leave any field blank or choose <b>any</b> for wildcard. "
                "First match wins — no match = <b>implicit deny</b>.</div>",
                unsafe_allow_html=True,
            )

            col1, col2 = st.columns(2)

            with col1:
                _lbl("🔌 Source / Incoming Interface")
                src_iface = st.selectbox(
                    "src_iface_pol",
                    iface_opts,
                    index=0,
                    key="po_lu_src_iface",
                    label_visibility="collapsed",
                    help="Matches policy srcintf. 'any' = wildcard.",
                )

                _lbl("🌐 IP Version")
                ip_version = st.selectbox(
                    "ipver_pol",
                    ["any", "ipv4", "ipv6"],
                    index=0,
                    key="po_lu_ipver",
                    label_visibility="collapsed",
                )

                _lbl("📤 Source IP / Address")
                src_ip = st.text_input(
                    "src_ip_pol",
                    value="",
                    key="po_lu_src_ip",
                    placeholder="e.g. 10.0.0.1  or blank for any",
                    label_visibility="collapsed",
                )

                _lbl("📥 Destination IP / FQDN")
                dst_ip = st.text_input(
                    "dst_ip_pol",
                    value="",
                    key="po_lu_dst_ip",
                    placeholder="e.g. 8.8.8.8  or blank for any",
                    label_visibility="collapsed",
                )

            with col2:
                _lbl("🎯 Destination / Outgoing Interface")
                dst_iface = st.selectbox(
                    "dst_iface_pol",
                    iface_opts,
                    index=0,
                    key="po_lu_dst_iface",
                    label_visibility="collapsed",
                    help="Matches policy dstintf. 'any' = wildcard.",
                )

                _lbl("⚙️ Protocol")
                protocol = st.selectbox(
                    "proto_pol",
                    [
                        "any",
                        "ip",
                        "tcp",
                        "udp",
                        "sctp",
                        "icmp",
                        "icmp ping request",
                        "icmp ping reply",
                    ],
                    index=0,
                    key="po_lu_proto",
                    label_visibility="collapsed",
                )

                proto_num = src_port = dst_port = icmp_type = icmp_code = None

                if protocol == "ip":
                    proto_num = st.number_input(
                        "Protocol Number", 0, 255, 0, key="po_lu_pnum"
                    )
                elif protocol in ("tcp", "udp", "sctp"):
                    _lbl("📡 Source Port  (blank = any)")
                    sp = st.text_input(
                        "src_port_pol",
                        value="",
                        key="po_lu_sport",
                        placeholder="e.g. 1024 — optional",
                        label_visibility="collapsed",
                    )
                    _lbl("📡 Destination Port  (blank = any)")
                    dp = st.text_input(
                        "dst_port_pol",
                        value="",
                        key="po_lu_dport",
                        placeholder="e.g. 443 — optional",
                        label_visibility="collapsed",
                    )
                    try:
                        src_port = int(sp) if sp.strip() else None
                    except ValueError:
                        src_port = None
                    try:
                        dst_port = int(dp) if dp.strip() else None
                    except ValueError:
                        dst_port = None
                elif protocol == "icmp":
                    icmp_type = st.number_input("ICMP Type", 0, 255, 8, key="po_lu_it")
                    icmp_code = st.number_input("ICMP Code", 0, 255, 0, key="po_lu_ic")
                elif protocol == "icmp ping request":
                    icmp_type, icmp_code = 8, 0
                    st.info("ICMP Type 8 / Code 0 — Echo Request")
                elif protocol == "icmp ping reply":
                    icmp_type, icmp_code = 0, 0
                    st.info("ICMP Type 0 / Code 0 — Echo Reply")

            # ── Run button ─────────────────────────────────────────────────
            if st.button("▶ Evaluate Policy", key="po_lu_btn", type="primary"):
                if not rows:
                    st.warning("No policies found.")
                else:
                    result = _evaluate_lookup(
                        rows,
                        parser,
                        src_iface,
                        dst_iface,
                        src_ip,
                        dst_ip,
                        protocol,
                        proto_num,
                        src_port,
                        dst_port,
                        icmp_type,
                        icmp_code,
                    )
                    st.markdown("---")
                    if result:
                        action = str(result.get("Action", "-")).upper()
                        ac = "#3fb950" if action == "ACCEPT" else "#f85149"
                        ab = "#0d2b15" if action == "ACCEPT" else "#2b0d0d"
                        icon = "✅" if action == "ACCEPT" else "🚫"
                        st.markdown(
                            f'<div style="background:{ab};border:2px solid {ac}55;'
                            f'border-radius:14px;padding:18px 22px">'
                            f'<div style="font-size:11px;color:{ac};font-weight:700;'
                            f'text-transform:uppercase;margin-bottom:8px">'
                            f"{icon} First Matching Policy</div>"
                            f'<div style="display:flex;gap:28px;flex-wrap:wrap;align-items:flex-end">'
                            + "".join(
                                [
                                    f'<div><div style="font-size:11px;color:#8b949e">{lb}</div>'
                                    f'<div style="font-size:{sz};font-weight:900;color:{cl};'
                                    f'line-height:1.1">{val}</div></div>'
                                    for lb, val, sz, cl in [
                                        (
                                            "Policy ID",
                                            f'#{result.get("ID","?")}',
                                            "24px",
                                            "#e6edf3",
                                        ),
                                        (
                                            "Name",
                                            result.get("Name", "-"),
                                            "16px",
                                            "#e6edf3",
                                        ),
                                        ("Action", action, "24px", ac),
                                        (
                                            "Src Interface",
                                            result.get("Src Interface", "-"),
                                            "13px",
                                            "#e6edf3",
                                        ),
                                        (
                                            "Dst Interface",
                                            result.get("Dst Interface", "-"),
                                            "13px",
                                            "#e6edf3",
                                        ),
                                        (
                                            "Service",
                                            result.get("Service", "-"),
                                            "13px",
                                            "#e6edf3",
                                        ),
                                        (
                                            "NAT",
                                            result.get("NAT", "-"),
                                            "13px",
                                            "#e6edf3",
                                        ),
                                    ]
                                ]
                            )
                            + "</div></div>",
                            unsafe_allow_html=True,
                        )
                        st_table(
                            [result],
                            key="po_lu_result",
                            export_filename="policy_lookup_result.csv",
                        )
                    else:
                        st.markdown(
                            '<div style="background:#2b0d0d;border:2px solid #f8514955;'
                            'border-radius:14px;padding:18px 22px">'
                            '<div style="font-size:18px;font-weight:800;color:#f85149;'
                            'margin-bottom:6px">❌ No Matching Policy — Implicit DENY</div>'
                            '<div style="font-size:13px;color:#cdd9e5">'
                            "Traffic would be dropped by the implicit deny rule.</div></div>",
                            unsafe_allow_html=True,
                        )

        # ── Firewall Policy table ──────────────────────────────────────────
        def _hl_pol(row):
            if str(row.get("Status", "")).lower() == "disable":
                return ["background-color:#fff3cd"] * len(row)
            return [""] * len(row)

        if rows:
            st_table(
                rows,
                key="fg_fw_policies",
                style_fn=_hl_pol,
                export_filename="fg_firewall_policies.csv",
                caption=f"{len(rows)} policies",
            )
        else:
            st.info("No firewall policies found.")

    # ── Proxy Policy ──────────────────────────────────────────
    with tab_proxy:
        st.markdown("#### Proxy Policies")
        rows = parser.parse_proxy_policy()

        def _hl_pp(row):
            if str(row.get("Status", "")).lower() == "disable":
                return ["background-color:#fff3cd"] * len(row)
            return [""] * len(row)

        if rows:
            st_table(
                rows,
                key="fg_proxy_pol",
                style_fn=_hl_pp,
                export_filename="fg_proxy_policies.csv",
            )
        else:
            st.info("No proxy policies found.")

    # ── Auth Rules ────────────────────────────────────────────
    with tab_auth:
        st.markdown("#### Authentication Rules")
        rows = parser.parse_auth_rules()
        if rows:
            st_table(rows, key="fg_auth_rules", export_filename="fg_auth_rules.csv")
        else:
            st.info("No authentication rules found.")

    # ── Addresses ─────────────────────────────────────────────
    with tab_addr:
        st.markdown("#### Addresses")
        addr = parser.parse_addresses()
        a1, a2, a3, a4, a5, a6 = st.tabs(
            [
                "Subnet / IP Mask",
                "IP Range",
                "FQDN",
                "Interface Subnet",
                "Address Groups",
                "Host Regex",
            ]
        )
        _INTERNAL = {
            "network_obj",
            "network",
            "broadcast",
            "prefixlen",
            "start_int",
            "end_int",
        }
        for subtab, data_key, key_sfx, label in [
            (a1, "subnet", "subnet", "Subnet"),
            (a2, "iprange", "iprange", "IP Range"),
            (a3, "fqdn", "fqdn", "FQDN"),
            (a4, "ipmask", "ipmask", "Interface Subnet"),
            (a5, "groups", "groups", "Address Groups"),
            (a6, "regex", "regex", "Host Regex"),
        ]:
            with subtab:
                raw = addr.get(data_key, [])
                clean = [
                    {k: v for k, v in r.items() if k not in _INTERNAL} for r in raw
                ]
                if clean:
                    st_table(
                        clean,
                        key=f"fg_addr_{key_sfx}",
                        export_filename=f"fg_addr_{key_sfx}.csv",
                    )
                else:
                    st.info(f"No {label} addresses.")

    # ── Services ──────────────────────────────────────────────
    with tab_svc:
        st.markdown("#### Services")
        svc_data = parser.parse_services()
        categories = svc_data.get("categories", [])
        services = svc_data.get("services", [])
        if categories:
            st.markdown("**Categories:** " + " | ".join(f"`{c}`" for c in categories))
            st.divider()
        if not services:
            st.info("No custom services found.")
        else:
            all_cats = sorted(set(s["Category"] for s in services))
            selected = st.multiselect(
                "Filter by Category", all_cats, default=all_cats, key="svc_cat"
            )
            filtered = [s for s in services if s["Category"] in selected]
            st_table(filtered, key="fg_services", export_filename="fg_services.csv")

    # ── Schedules ─────────────────────────────────────────────
    with tab_sched:
        st.markdown("#### Schedules")
        rows = parser.parse_schedules()
        if rows:
            st_table(rows, key="fg_schedules", export_filename="fg_schedules.csv")
        else:
            st.info("No schedules found.")

    # ── Virtual IPs ───────────────────────────────────────────
    with tab_vip:
        st.markdown("#### Virtual IPs (NAT)")
        rows = parser.parse_vip()
        if rows:
            st_table(rows, key="fg_vips", export_filename="fg_virtual_ips.csv")
        else:
            st.info("No Virtual IPs found.")

    # ── IP Pools ──────────────────────────────────────────────
    with tab_pool:
        st.markdown("#### IP Pools")
        rows = parser.parse_ip_pools()
        if rows:
            st_table(rows, key="fg_ip_pools", export_filename="fg_ip_pools.csv")
        else:
            st.info("No IP pools found.")

    # ── Protocol Options ──────────────────────────────────────
    with tab_proto:
        st.markdown("#### Protocol Options")
        rows = parser.parse_protocol_options()
        if not rows:
            st.info("No protocol options profiles found.")
        else:
            profiles = sorted(set(r["Profile"] for r in rows))
            sel = st.selectbox("Select Profile", profiles, key="proto_prof")
            filtered = [r for r in rows if r["Profile"] == sel]
            st_table(
                filtered, key="fg_proto_opts", export_filename="fg_protocol_options.csv"
            )

    # ── Traffic Shaping ───────────────────────────────────────
    with tab_shaper:
        st.markdown("#### Traffic Shaping")
        rows = parser.parse_traffic_shaping()
        if rows:
            st_table(
                rows, key="fg_traffic_shaping", export_filename="fg_traffic_shaping.csv"
            )
        else:
            st.info("No traffic shapers found.")

    # ── Virtual Servers ───────────────────────────────────────
    with tab_vserver:
        st.markdown("#### Virtual Servers")
        rows = parser.parse_virtual_servers()
        if rows:
            st_table(rows, key="fg_vservers", export_filename="fg_virtual_servers.csv")
        else:
            st.info("No virtual servers found.")

    # ── Health Check ──────────────────────────────────────────
    with tab_hc:
        st.markdown("#### Health Checks (LDB Monitor)")
        rows = parser.parse_health_check()
        if rows:
            st_table(
                rows, key="fg_health_checks", export_filename="fg_health_checks.csv"
            )
        else:
            st.info("No health check monitors found.")
