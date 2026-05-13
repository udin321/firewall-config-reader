import streamlit as st
import pandas as pd
import ipaddress


def _show_table(rows: list, empty_msg: str = "Not configured"):
    if not rows:
        st.info(empty_msg)
        return
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _highlight_disabled(df: pd.DataFrame):
    def highlight(row):
        if str(row.get("Status", "")).lower() == "disable":
            return ["background-color: #fff3cd"] * len(row)
        return [""] * len(row)

    return df.style.apply(highlight, axis=1)


def ip_in_subnet(ip, subnet_obj):

    try:
        return ipaddress.IPv4Address(ip) in subnet_obj

    except:
        return False


def ip_in_range(ip, start_int, end_int):

    try:

        ip_int = int(ipaddress.IPv4Address(ip))

        return start_int <= ip_int <= end_int

    except:
        return False


def resolve_address_match(ip, addr_obj):

    addr_type = str(addr_obj.get("Type", "")).lower()

    # =====================================================
    # SUBNET
    # =====================================================

    if addr_type == "subnet":

        subnet_obj = addr_obj.get("network_obj")

        if subnet_obj:

            return ip_in_subnet(ip, subnet_obj)

    # =====================================================
    # IP RANGE
    # =====================================================

    elif addr_type == "ip range":

        start_int = addr_obj.get("start_int")
        end_int = addr_obj.get("end_int")

        if start_int is not None and end_int is not None:

            return ip_in_range(ip, start_int, end_int)

    return False


def evaluate_policy_lookup(
    policies,
    parser,
    incoming_interface,
    ip_version,
    protocol,
    protocol_number,
    src_port,
    dst_port,
    src_ip,
    dst_ip,
    icmp_type,
    icmp_code,
):

    addresses = parser.parse_addresses()

    all_addr_objects = addresses.get("subnet", []) + addresses.get("iprange", [])

    # =====================================================
    # POLICY ORDER: TOP -> BOTTOM
    # =====================================================

    for policy in policies:

        # =================================================
        # STATUS CHECK
        # =================================================

        if str(policy.get("Status", "")).lower() == "disable":

            continue

        # =================================================
        # INCOMING INTERFACE MATCH
        # =================================================

        srcintf = str(policy.get("Source Interface", "")).lower()

        if incoming_interface and incoming_interface.lower() not in srcintf:

            continue

        # =================================================
        # SOURCE ADDRESS MATCH
        # =================================================

        srcaddr = str(policy.get("Source Address", ""))

        src_match = False

        if srcaddr.lower() == "all":

            src_match = True

        else:

            for addr_obj in all_addr_objects:

                if addr_obj["Name"] in srcaddr:

                    if resolve_address_match(src_ip, addr_obj):

                        src_match = True
                        break

        if not src_match:
            continue

        # =================================================
        # DESTINATION ADDRESS MATCH
        # =================================================

        dstaddr = str(policy.get("Destination Address", ""))

        dst_match = False

        if dstaddr.lower() == "all":

            dst_match = True

        else:

            for addr_obj in all_addr_objects:

                if addr_obj["Name"] in dstaddr:

                    if resolve_address_match(dst_ip, addr_obj):

                        dst_match = True
                        break

        if not dst_match:
            continue

        # =================================================
        # MATCH FOUND
        # =================================================

        return {
            "ID": policy.get("ID", "-"),
            "Name": policy.get("Name", "-"),
            "Action": policy.get("Action", "-"),
        }

    # =====================================================
    # IMPLICIT DENY
    # =====================================================

    return None


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

    with tab_fw:
        st.markdown("#### Firewall Policies")

        rows = parser.parse_policies()

        # ======================================================
        # POLICY LOOKUP
        # ======================================================

        with st.expander("🔍 Policy Lookup", expanded=False):

            col1, col2 = st.columns(2)

            incoming_intf = col1.text_input("Incoming Interface", key="lookup_in_intf")

            ip_version = col2.selectbox(
                "IP Version", ["ipv4", "ipv6"], key="lookup_ipver"
            )

            protocol = st.selectbox(
                "Protocol",
                [
                    "ip",
                    "tcp",
                    "udp",
                    "sctp",
                    "icmp",
                    "icmp ping request",
                    "icmp ping reply",
                ],
                key="lookup_proto",
            )

            protocol_number = src_port = dst_port = icmp_type = icmp_code = None

            # ==================================================
            # PROTOCOL OPTIONS
            # ==================================================

            if protocol == "ip":

                protocol_number = st.number_input(
                    "Protocol Number", 0, 255, 0, key="lookup_proto_num"
                )

            elif protocol in ["tcp", "udp", "sctp"]:

                c1, c2 = st.columns(2)
                src_port = c1.number_input("Source Port", 1, 65535, 1)
                dst_port = c2.number_input("Destination Port", 1, 65535, 80)

            elif protocol == "icmp":

                c1, c2 = st.columns(2)
                icmp_type = c1.number_input("ICMP Type", 0, 255, 8)
                icmp_code = c2.number_input("ICMP Code", 0, 255, 0)

            c1, c2 = st.columns(2)
            src_ip = c1.text_input("Source IP / Address")
            dst_ip = c2.text_input("Destination IP / FQDN")

        # ==================================================
        # SOURCE / DESTINATION
        # =================================================

        # ==================================================
        # LOOKUP BUTTON
        # ==================================================

        if st.button("Evaluate Policy"):

            result = evaluate_policy_lookup(
                policies=rows,
                parser=parser,
                incoming_interface=incoming_intf,
                ip_version=ip_version,
                protocol=protocol,
                protocol_number=protocol_number,
                src_port=src_port,
                dst_port=dst_port,
                src_ip=src_ip,
                dst_ip=dst_ip,
                icmp_type=icmp_type,
                icmp_code=icmp_code,
            )

            st.markdown("### Result")

            if result:
                st.success(f"""
ID: {result['ID']}
Name: {result['Name']}
Action: {result['Action']}
""")
            else:
                st.error("Implicit Deny")

        # ===============================
        # POLICY TABLE
        # ===============================
        if rows:

            df = pd.DataFrame(rows)

            st.dataframe(
                _highlight_disabled(df), use_container_width=True, hide_index=True
            )

            # ----------------------------
            # CSV EXPORT (Firewall Policies)
            # ----------------------------
            csv = df.to_csv(index=False).encode("utf-8")

            st.download_button(
                "⬇ Export Firewall Policies (CSV)",
                data=csv,
                file_name="firewall_policies.csv",
                mime="text/csv",
            )

        else:
            st.info("No firewall policies found.")

    with tab_proxy:
        st.markdown("#### Proxy Policies")
        rows = parser.parse_proxy_policy()
        if rows:
            st.dataframe(
                _highlight_disabled(pd.DataFrame(rows)),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No proxy policies found.")

    with tab_auth:
        st.markdown("#### Authentication Rules")
        _show_table(parser.parse_auth_rules(), "No authentication rules found.")

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

        # =========================
        # SUBNET
        # =========================
        with a1:
            rows = addr.get("subnet", [])
            _show_table(rows, "No subnet addresses.")

            if rows:
                st.download_button(
                    "⬇ Export Subnet CSV",
                    pd.DataFrame(rows).to_csv(index=False).encode("utf-8"),
                    file_name="subnet.csv",
                    mime="text/csv",
                    key="dl_subnet",
                )

        # =========================
        # IP RANGE
        # =========================
        with a2:
            rows = addr.get("iprange", [])
            _show_table(rows, "No IP range addresses.")

            if rows:
                st.download_button(
                    "⬇ Export IP Range CSV",
                    pd.DataFrame(rows).to_csv(index=False).encode("utf-8"),
                    file_name="iprange.csv",
                    mime="text/csv",
                    key="dl_iprange",
                )

        # =========================
        # FQDN
        # =========================
        with a3:
            rows = addr.get("fqdn", [])
            _show_table(rows, "No FQDN addresses.")

            if rows:
                st.download_button(
                    "⬇ Export FQDN CSV",
                    pd.DataFrame(rows).to_csv(index=False).encode("utf-8"),
                    file_name="fqdn.csv",
                    mime="text/csv",
                    key="dl_fqdn",
                )

        # =========================
        # INTERFACE SUBNET
        # =========================
        with a4:
            rows = addr.get("ipmask", [])
            _show_table(rows, "No interface subnet addresses.")

            if rows:
                st.download_button(
                    "⬇ Export Interface Subnet CSV",
                    pd.DataFrame(rows).to_csv(index=False).encode("utf-8"),
                    file_name="ipmask.csv",
                    mime="text/csv",
                    key="dl_ipmask",
                )

        # =========================
        # GROUPS
        # =========================
        with a5:
            rows = addr.get("groups", [])
            _show_table(rows, "No address groups.")

            if rows:
                st.download_button(
                    "⬇ Export Groups CSV",
                    pd.DataFrame(rows).to_csv(index=False).encode("utf-8"),
                    file_name="groups.csv",
                    mime="text/csv",
                    key="dl_groups",
                )

        # =========================
        # REGEX
        # =========================
        with a6:
            rows = addr.get("regex", [])
            _show_table(rows, "No host regex addresses.")

            if rows:
                st.download_button(
                    "⬇ Export Regex CSV",
                    pd.DataFrame(rows).to_csv(index=False).encode("utf-8"),
                    file_name="regex.csv",
                    mime="text/csv",
                    key="dl_regex",
                )

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
                "Filter by Category", all_cats, default=all_cats, key="svc_cat_filter"
            )
            filtered = [s for s in services if s["Category"] in selected]
            _show_table(filtered, "No services match the filter.")

    with tab_sched:
        st.markdown("#### Schedules")
        _show_table(parser.parse_schedules(), "No schedules found.")

    with tab_vip:
        st.markdown("#### Virtual IPs (NAT)")
        _show_table(parser.parse_vip(), "No Virtual IPs found.")

    with tab_pool:
        st.markdown("#### IP Pools")
        _show_table(parser.parse_ip_pools(), "No IP pools found.")

    with tab_proto:
        st.markdown("#### Protocol Options")
        rows = parser.parse_protocol_options()
        if not rows:
            st.info("No protocol options profiles found.")
        else:
            profiles = sorted(set(r["Profile"] for r in rows))
            selected_profile = st.selectbox(
                "Select Profile", profiles, key="proto_profile"
            )
            filtered = [r for r in rows if r["Profile"] == selected_profile]
            _show_table(filtered)

    with tab_shaper:
        st.markdown("#### Traffic Shaping")
        _show_table(parser.parse_traffic_shaping(), "No traffic shapers found.")

    with tab_vserver:
        st.markdown("#### Virtual Servers")
        _show_table(parser.parse_virtual_servers(), "No virtual servers found.")

    with tab_hc:
        st.markdown("#### Health Checks (LDB Monitor)")
        _show_table(parser.parse_health_check(), "No health check monitors found.")
