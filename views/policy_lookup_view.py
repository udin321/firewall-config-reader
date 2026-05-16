"""
views/policy_lookup_view.py
FortiGate — Policy Lookup tab.

* Dropdown of ALL interfaces (src + dst) from config system interface + zones
* Every field blank / "any" = wildcard
* AND logic across ALL parameters: src-iface, dst-iface, src-addr, dst-addr, protocol
* Top-to-bottom evaluation — FIRST match wins
* Result card shows Policy ID, Name, Action, Src/Dst Interface, Service, NAT
* Full searchable + exportable policy list below
* Implicit deny when no policy matches
"""

from __future__ import annotations
import ipaddress
import streamlit as st
import pandas as pd
from views.table_utils import st_table

# ═══════════════════════════════════════════════════════════════════════════════
#  IP helpers
# ═══════════════════════════════════════════════════════════════════════════════


def _int(ip: str):
    try:
        return int(ipaddress.IPv4Address(ip.strip()))
    except Exception:
        return None


def _net(val: str):
    v = val.strip()
    for fmt in (v, f"{v}/32"):
        try:
            return ipaddress.IPv4Network(fmt, strict=False)
        except ValueError:
            pass
    return None


def _in_resolved(test_ip: str, resolved: list) -> bool:
    """Empty list = 'any' = always True."""
    if not resolved:
        return True
    tip = _int(test_ip)
    if tip is None:
        return False
    for obj in resolved:
        if isinstance(obj, ipaddress.IPv4Network) and tip in obj:
            return True
        if isinstance(obj, tuple) and obj[0] <= tip <= obj[1]:
            return True
    return False


def _resolve(val: str, fg, addr_map: dict) -> list:
    v = val.strip()
    if v.lower() in ("any", "all", ""):
        return []
    n = _net(v)
    if n:
        return [n]
    return fg.resolve_address(v, addr_map)


def _rep(resolved: list) -> str | None:
    for obj in resolved:
        if isinstance(obj, ipaddress.IPv4Network):
            h = list(obj.hosts())
            return str(h[0]) if h else str(obj.network_address)
        if isinstance(obj, tuple):
            return str(ipaddress.IPv4Address(obj[0]))
    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  AND-condition matchers
# ═══════════════════════════════════════════════════════════════════════════════


def _iface_ok(pol_val: str, user_val: str) -> bool:
    """
    True when user chose 'any', or the policy interface list contains 'any',
    or the user-chosen interface appears in the policy's comma-separated list.
    """
    if user_val.lower() == "any":
        return True
    pl = [x.strip().lower() for x in pol_val.split(",")]
    return "any" in pl or user_val.lower() in pl


def _addr_ok(pol_str: str, user_res: list, fg, addr_map: dict) -> bool:
    """
    True when user supplied no address (any), or the policy address resolves
    to a range that contains the user-supplied IP.
    """
    if not user_res:
        return True  # blank input → wildcard
    rep = _rep(user_res)
    if rep is None:
        return True
    for name in [n.strip() for n in pol_str.split(",")]:
        if name.lower() in ("all", "any"):
            return True
        res = fg.resolve_address(name, addr_map)
        if not res or _in_resolved(rep, res):
            return True
    return False


def _proto_ok(pol_svc: str, proto_key: str) -> bool:
    """True when user chose 'any', or the policy service covers the protocol."""
    if proto_key == "any":
        return True
    svc = pol_svc.upper()
    return any(x in svc for x in ("ALL", "ANY")) or proto_key.upper() in svc


# ═══════════════════════════════════════════════════════════════════════════════
#  UI label helper
# ═══════════════════════════════════════════════════════════════════════════════


def _lbl(txt: str):
    st.markdown(
        f'<p style="margin:8px 0 3px;font-size:11px;color:#8b949e;'
        f'font-weight:700;text-transform:uppercase">{txt}</p>',
        unsafe_allow_html=True,
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  Main render
# ═══════════════════════════════════════════════════════════════════════════════


def render_policy_lookup(fg):
    st.markdown(
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">'
        '<span style="font-size:22px">🔍</span>'
        '<span style="font-size:20px;font-weight:800;color:#e6edf3">Policy Lookup</span>'
        "</div>"
        '<div style="font-size:13px;color:#8b949e;margin-bottom:14px">'
        "Simulates traffic and finds the <b>first matching</b> policy (top-to-bottom). "
        "Leave any field blank or choose <b>any</b> to use it as a wildcard. "
        "All conditions are combined with <b>AND</b> logic. "
        "No match = <b>implicit deny</b>.</div>",
        unsafe_allow_html=True,
    )

    # ── Pre-load data ──────────────────────────────────────────────────────
    iface_names = fg.get_interface_names()  # ALL interfaces + zones from config
    addr_map = fg.get_address_objects()
    policies = fg.parse_policies()  # in top-to-bottom config order

    iface_opts = ["any"] + iface_names

    # ── Parameter form ─────────────────────────────────────────────────────
    st.markdown(
        '<div style="background:#161b22;border:1px solid #30363d;'
        'border-radius:12px;padding:16px 18px;margin-bottom:14px">',
        unsafe_allow_html=True,
    )

    c1, c2 = st.columns(2)

    with c1:
        _lbl("🔌 Source / Incoming Interface")
        src_iface = st.selectbox(
            "src_iface",
            iface_opts,
            index=0,
            key="lu_iface",
            label_visibility="collapsed",
            help="Interface traffic arrives on. Matches policy 'srcintf'. 'any' = wildcard.",
        )

        _lbl("🌐 IP Version")
        ip_ver = st.selectbox(
            "ipver",
            ["any", "IPv4", "IPv6"],
            index=0,
            key="lu_ipver",
            label_visibility="collapsed",
        )

        _lbl("📤 Source Address / Subnet")
        src_addr = st.text_input(
            "src",
            value="",
            key="lu_src",
            placeholder="10.1.0.0/24  or blank for any",
            label_visibility="collapsed",
        )

        _lbl("📥 Destination Address / Subnet")
        dst_addr = st.text_input(
            "dst",
            value="",
            key="lu_dst",
            placeholder="192.168.1.100  or blank for any",
            label_visibility="collapsed",
        )

    with c2:
        _lbl("🎯 Destination / Outgoing Interface")
        dst_iface = st.selectbox(
            "dst_iface",
            iface_opts,
            index=0,
            key="lu_dst_iface",
            label_visibility="collapsed",
            help="Interface traffic exits on. Matches policy 'dstintf'. 'any' = wildcard.",
        )

        _lbl("⚙️ Protocol")
        protocol = st.selectbox(
            "proto",
            [
                "any",
                "TCP",
                "UDP",
                "ICMP",
                "ICMP Ping Request",
                "ICMP Ping Reply",
                "SCTP",
                "IP (custom number)",
            ],
            index=0,
            key="lu_proto",
            label_visibility="collapsed",
        )

        src_port = dst_port = icmp_type = icmp_code = proto_num = None

        if protocol in ("TCP", "UDP", "SCTP"):
            _lbl("📡 Source Port  (blank = any)")
            sp = st.text_input(
                "sp",
                "",
                key="lu_sport",
                placeholder="e.g. 1024  —  leave blank for any",
                label_visibility="collapsed",
            )
            _lbl("📡 Destination Port  (blank = any)")
            dp = st.text_input(
                "dp",
                "",
                key="lu_dport",
                placeholder="e.g. 443  —  leave blank for any",
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

        elif protocol in ("ICMP", "ICMP Ping Request", "ICMP Ping Reply"):
            if protocol == "ICMP":
                icmp_type = st.slider("ICMP Type (0–255)", 0, 255, 0, key="lu_it")
                icmp_code = st.slider("ICMP Code (0–255)", 0, 255, 0, key="lu_ic")
            elif protocol == "ICMP Ping Request":
                icmp_type, icmp_code = 8, 0
                st.info("Type 8 / Code 0 — Echo Request")
            else:
                icmp_type, icmp_code = 0, 0
                st.info("Type 0 / Code 0 — Echo Reply")

        elif protocol == "IP (custom number)":
            proto_num = st.slider("Protocol Number (0–255)", 0, 255, 0, key="lu_pnum")

    st.markdown("</div>", unsafe_allow_html=True)

    # ── Always show full policy list ───────────────────────────────────────
    _all_policies_expander(policies)

    run = st.button("🔎 Run Lookup", key="lu_run", type="primary")
    if not run:
        return

    if not policies:
        st.warning("⚠️ No firewall policies found in configuration.")
        return

    # ── Normalise protocol key ─────────────────────────────────────────────
    _PMAP = {
        "any": "any",
        "TCP": "tcp",
        "UDP": "udp",
        "SCTP": "sctp",
        "ICMP": "icmp",
        "ICMP Ping Request": "icmp",
        "ICMP Ping Reply": "icmp",
        "IP (custom number)": str(proto_num or 0),
    }
    proto_key = _PMAP.get(protocol, "any")

    # ── Resolve user-supplied IP inputs ───────────────────────────────────
    src_res = _resolve(src_addr, fg, addr_map)
    dst_res = _resolve(dst_addr, fg, addr_map)

    # ══════════════════════════════════════════════════════════════════════
    #  Top-to-bottom policy scan  —  ALL conditions combined with AND
    #  Conditions:
    #    1. src interface  (srcintf)
    #    2. dst interface  (dstintf)
    #    3. source address (srcaddr)
    #    4. dest address   (dstaddr)
    #    5. protocol/service
    #
    #  First matching enabled policy wins.
    #  If no match → implicit deny.
    # ══════════════════════════════════════════════════════════════════════
    match = None
    for pol in policies:
        # skip disabled policies
        if str(pol.get("Status", "Enable")).lower() == "disable":
            continue

        # AND 1 — source / incoming interface
        if not _iface_ok(str(pol.get("Src Interface", "any")), src_iface):
            continue

        # AND 2 — destination / outgoing interface
        if not _iface_ok(str(pol.get("Dst Interface", "any")), dst_iface):
            continue

        # AND 3 — source address
        if not _addr_ok(str(pol.get("Source", "any")), src_res, fg, addr_map):
            continue

        # AND 4 — destination address
        if not _addr_ok(str(pol.get("Destination", "any")), dst_res, fg, addr_map):
            continue

        # AND 5 — protocol / service
        if not _proto_ok(str(pol.get("Service", "ALL")), proto_key):
            continue

        match = pol
        break  # first match — stop scanning

    # ══════════════════════════════════════════════════════════════════════
    #  Result
    # ══════════════════════════════════════════════════════════════════════
    st.markdown("---")

    # Parameters summary caption
    params_parts = [
        f"Src Interface: **{src_iface}**",
        f"Dst Interface: **{dst_iface}**",
        f"IP Version: **{ip_ver}**",
        f"Source: **{src_addr or 'any'}**",
        f"Destination: **{dst_addr or 'any'}**",
        f"Protocol: **{protocol}**",
    ]
    if src_port is not None:
        params_parts.append(f"Src Port: **{src_port}**")
    if dst_port is not None:
        params_parts.append(f"Dst Port: **{dst_port}**")
    if icmp_type is not None:
        params_parts.append(f"ICMP Type: **{icmp_type}** / Code: **{icmp_code}**")
    st.caption("  ·  ".join(params_parts))

    if match:
        action = str(match.get("Action", "-")).upper()
        ac = "#3fb950" if action == "ACCEPT" else "#f85149"
        ab = "#0d2b15" if action == "ACCEPT" else "#2b0d0d"
        icon = "✅" if action == "ACCEPT" else "🚫"

        st.markdown(
            f'<div style="background:{ab};border:2px solid {ac}55;'
            f'border-radius:14px;padding:20px 24px;margin:10px 0">'
            f'<div style="font-size:11px;color:{ac};font-weight:700;'
            f'text-transform:uppercase;letter-spacing:.8px;margin-bottom:10px">'
            f"{icon} First Matching Policy</div>"
            f'<div style="display:flex;gap:36px;flex-wrap:wrap;align-items:flex-end">'
            + "".join(
                [
                    f'<div><div style="font-size:11px;color:#8b949e">{lbl}</div>'
                    f'<div style="font-size:{sz};font-weight:900;color:{col};'
                    f'line-height:1.1">{val}</div></div>'
                    for lbl, val, sz, col in [
                        ("Policy ID", f'#{match.get("ID","?")}', "28px", "#e6edf3"),
                        ("Name", match.get("Name", "-"), "18px", "#e6edf3"),
                        ("Action", action, "28px", ac),
                        (
                            "Src Interface",
                            match.get("Src Interface", "-"),
                            "13px",
                            "#e6edf3",
                        ),
                        (
                            "Dst Interface",
                            match.get("Dst Interface", "-"),
                            "13px",
                            "#e6edf3",
                        ),
                        ("Service", match.get("Service", "-"), "13px", "#e6edf3"),
                        ("NAT", match.get("NAT", "-"), "13px", "#e6edf3"),
                    ]
                ]
            )
            + "</div></div>",
            unsafe_allow_html=True,
        )

        st.markdown("**Complete policy detail:**")
        st_table([match], key="lu_match", export_filename="policy_match.csv")

    else:
        # ── Implicit Deny ──────────────────────────────────────────────────
        st.markdown(
            '<div style="background:#2b0d0d;border:2px solid #f8514955;'
            'border-radius:14px;padding:20px 24px;margin:10px 0">'
            '<div style="font-size:18px;font-weight:800;color:#f85149;margin-bottom:8px">'
            "❌ No Matching Policy — Traffic DENIED (Implicit Deny)</div>"
            '<div style="font-size:13px;color:#cdd9e5">'
            "The simulated traffic did not match any enabled policy.<br>"
            "Traffic would be dropped by the firewall's implicit deny rule at the "
            "bottom of the policy list.</div></div>",
            unsafe_allow_html=True,
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  All-policies expander (always visible)
# ═══════════════════════════════════════════════════════════════════════════════


def _all_policies_expander(policies: list):
    st.markdown("---")
    with st.expander(
        f"📋 All Policies ({len(policies)} total) — search & export",
        expanded=False,
    ):
        if policies:
            st_table(policies, key="lu_all_pol", export_filename="all_policies.csv")
        else:
            st.info("No policies found.")
