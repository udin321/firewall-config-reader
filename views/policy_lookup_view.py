"""
views/policy_lookup_view.py
Advanced policy-lookup tab for FortiGate configurations.
"""
from __future__ import annotations
import ipaddress
import re
import streamlit as st
import pandas as pd

from views.csv_export import render_csv_button


# ── IP / subnet helpers ───────────────────────────────────────────────────────
def _expand_subnet(value: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Return host addresses in a subnet or a single address list."""
    value = value.strip()
    try:
        net = ipaddress.ip_network(value, strict=False)
        # For large subnets cap at 65536 hosts to avoid memory issues
        hosts = list(net.hosts()) if net.num_addresses <= 65536 else []
        if not hosts:
            hosts = [net.network_address, net.broadcast_address]
        return hosts
    except ValueError:
        pass
    try:
        return [ipaddress.ip_address(value)]
    except ValueError:
        return []


def _ip_in_range(test_ip: str, target: str) -> bool:
    """
    Check if test_ip falls within target which may be:
    - a single IP
    - a CIDR subnet
    - a range like "10.0.0.1-10.0.0.10"
    - "any"
    """
    if target.lower() in ("any", "all", ""):
        return True
    test_ip = test_ip.strip()
    target = target.strip()
    if "-" in target and not target.startswith("-"):
        parts = target.split("-", 1)
        try:
            start = ipaddress.ip_address(parts[0].strip())
            end   = ipaddress.ip_address(parts[1].strip())
            addr  = ipaddress.ip_address(test_ip)
            return start <= addr <= end
        except ValueError:
            pass
    try:
        net = ipaddress.ip_network(target, strict=False)
        return ipaddress.ip_address(test_ip) in net
    except ValueError:
        pass
    return test_ip == target


def _port_in_range(port: int, spec: str) -> bool:
    """
    spec can be "any", a single port, or "1000-2000".
    """
    if spec.lower() in ("any", "all", ""):
        return True
    spec = spec.strip()
    if "-" in spec:
        parts = spec.split("-", 1)
        try:
            return int(parts[0]) <= port <= int(parts[1])
        except ValueError:
            pass
    try:
        return port == int(spec)
    except ValueError:
        return False


# ── Main render function ───────────────────────────────────────────────────────
def render_policy_lookup(fg):
    """
    Render the Policy Lookup tab.
    fg: FortiGateParser instance.
    """
    st.subheader("🔍 Policy Lookup")
    st.caption("Simulate traffic and find which firewall policy (if any) would match it.")

    # ── Gather interface list ──────────────────────────────────────────────
    try:
        ifaces_raw = fg.get_interfaces()
        iface_names = ["any"] + sorted({r.get("Name","") for r in ifaces_raw if r.get("Name")})
    except Exception:
        iface_names = ["any"]

    # ── Gather policies ───────────────────────────────────────────────────
    try:
        policies = fg.get_policies()          # returns list[dict]
    except Exception:
        policies = []

    # ── Input form ────────────────────────────────────────────────────────
    with st.expander("🛠️ Lookup Parameters", expanded=True):
        col1, col2 = st.columns(2)

        with col1:
            ip_version = st.selectbox("IP Version", ["IPv4", "IPv6"], key="lu_ipver")
            src_iface  = st.selectbox("Incoming Interface", iface_names, key="lu_iface")
            src_addr   = st.text_input("Source Address / Subnet (e.g. 10.1.1.5 or 10.1.1.0/24 or any)",
                                       value="any", key="lu_src")
            dst_addr   = st.text_input("Destination Address / FQDN / Subnet",
                                       value="any", key="lu_dst")

        with col2:
            protocol = st.selectbox("Protocol",
                                    ["TCP", "UDP", "ICMP", "ICMP Ping Request",
                                     "ICMP Ping Reply", "SCTP", "IP (custom number)"],
                                    key="lu_proto")

            src_port = dst_port = icmp_type = icmp_code = proto_num = None

            if protocol in ("TCP", "UDP", "SCTP"):
                src_port = st.text_input("Source Port (number or range, or 'any')",
                                         value="any", key="lu_sport")
                dst_port = st.text_input("Destination Port (number or range, or 'any')",
                                         value="any", key="lu_dport")
            elif protocol in ("ICMP", "ICMP Ping Request", "ICMP Ping Reply"):
                if protocol == "ICMP":
                    icmp_type = st.slider("ICMP Type (0-255)", 0, 255, 0, key="lu_icmp_type")
                    icmp_code = st.slider("ICMP Code (0-255)", 0, 255, 0, key="lu_icmp_code")
                elif protocol == "ICMP Ping Request":
                    icmp_type, icmp_code = 8, 0
                    st.info("ICMP Type 8 / Code 0 (Echo Request)")
                else:
                    icmp_type, icmp_code = 0, 0
                    st.info("ICMP Type 0 / Code 0 (Echo Reply)")
            elif protocol == "IP (custom number)":
                proto_num = st.slider("Protocol Number (0-255)", 0, 255, 0, key="lu_protonum")

    run_lookup = st.button("🔎 Run Lookup", key="lu_run")

    if not run_lookup:
        return

    if not policies:
        st.warning("No policies found in the configuration.")
        return

    # ── Proto normalisation ────────────────────────────────────────────────
    PROTO_MAP = {
        "TCP": "tcp", "UDP": "udp", "SCTP": "sctp",
        "ICMP": "icmp", "ICMP Ping Request": "icmp", "ICMP Ping Reply": "icmp",
        "IP (custom number)": str(proto_num) if proto_num is not None else "0",
    }
    proto_key = PROTO_MAP[protocol]

    # ── Resolve source / destination to individual IPs ─────────────────────
    def resolve(addr_str: str):
        if addr_str.strip().lower() in ("any", "all", ""):
            return ["any"]
        # FQDN — keep as-is
        if re.match(r"^[a-zA-Z].*\.[a-zA-Z]{2,}$", addr_str) and "/" not in addr_str:
            return [addr_str]
        return [str(h) for h in _expand_subnet(addr_str)] or [addr_str]

    src_ips = resolve(src_addr)
    dst_ips = resolve(dst_addr)

    matched_policies = []
    sample_src = src_ips[0]
    sample_dst = dst_ips[0]

    for pol in policies:
        # Interface match
        pol_srcif = str(pol.get("srcintf", "any"))
        if src_iface != "any" and pol_srcif not in ("any", src_iface):
            continue

        # Source address match (simplified against first sample IP)
        pol_src = str(pol.get("srcaddr", "any"))
        if sample_src != "any" and not _ip_in_range(sample_src, pol_src):
            continue

        # Destination address match
        pol_dst = str(pol.get("dstaddr", "any"))
        if sample_dst != "any" and not _ip_in_range(sample_dst, pol_dst):
            continue

        # Protocol / service match (simplified: check service name or "ALL")
        pol_service = str(pol.get("service", "ALL")).upper()
        if pol_service not in ("ALL", "ANY"):
            if proto_key not in pol_service.lower():
                continue

        # Port match (only if policy has explicit port columns)
        if src_port and src_port != "any":
            pol_sport = str(pol.get("source_port", "any"))
            try:
                if not _port_in_range(int(src_port), pol_sport):
                    continue
            except ValueError:
                pass
        if dst_port and dst_port != "any":
            pol_dport = str(pol.get("dest_port", "any"))
            try:
                if not _port_in_range(int(dst_port), pol_dport):
                    continue
            except ValueError:
                pass

        matched_policies.append(pol)

    # ── Results ───────────────────────────────────────────────────────────
    st.markdown("---")
    if matched_policies:
        st.success(f"✅ {len(matched_policies)} matching polic{'y' if len(matched_policies)==1 else 'ies'} found")

        # Expand source / destination host counts
        src_count = len(src_ips) if src_ips[0] != "any" else "∞"
        dst_count = len(dst_ips) if dst_ips[0] != "any" else "∞"
        st.caption(f"Source resolved to **{src_count}** host(s) | Destination resolved to **{dst_count}** host(s)")

        df = pd.DataFrame(matched_policies)
        st.dataframe(df, use_container_width=True, hide_index=True)
        render_csv_button(matched_policies, filename="policy_lookup_results.csv",
                          label="⬇️ Export Matches CSV", key="lu_csv")
    else:
        st.error("❌ No matching policy found — traffic would be DENIED.")
        st.info("The traffic does not match any configured firewall policy.")
