import streamlit as st


def render_summary(parser, vendor="FortiGate"):

    hostname = parser.get_hostname()

    # DNS
    try:
        dns = parser.get_dns()
        dns_primary = dns.get("primary", "Unknown")
        dns_secondary = dns.get("secondary", "Unknown")
    except:
        dns_primary = "Unknown"
        dns_secondary = "Unknown"

    # WAN IP
    try:
        wan_ip = parser.get_wan_ip()
    except:
        wan_ip = "Unknown"

    # Serial Number
    try:
        serial = parser.get_serial_number()
    except:
        serial = "Unknown"

    # Firmware Version
    try:
        firmware = parser.get_firmware_version()
    except:
        firmware = "Unknown"

    st.subheader("📊 Overview")

    col1, col2, col3 = st.columns(3)

    col1.metric("Hostname", hostname)
    col2.metric("DNS Servers", f"P: {dns_primary}\nS: {dns_secondary}")
    col3.metric("WAN IP", wan_ip)

    col4, col5 = st.columns(2)

    col4.metric("Serial Number", serial)
    col5.metric("Firmware", firmware)


def render_device_details(parser):
    """Render full device details card — FortiGate specific."""

    serial = parser.get_serial_number()
    firmware = parser.get_firmware_version()
    wan_ip = parser.get_wan_ip()
    ha = parser.get_ha_config()
    dns = parser.get_dns()

    st.subheader("🖥️ Device Details")

    # ── Row 1: Basic info ──────────────────────────────────────────────
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("**Hostname**")
        st.code(parser.get_hostname(), language=None)
    with c2:
        st.markdown("**Serial Number**")
        st.code(serial, language=None)
    with c3:
        st.markdown("**Firmware Version**")
        st.code(firmware, language=None)

    # ── Row 2: WAN + DNS ───────────────────────────────────────────────
    c4, c5, c6 = st.columns(3)
    with c4:
        st.markdown("**WAN IP / Netmask**")
        st.code(wan_ip, language=None)
    with c5:
        st.markdown("**Primary DNS**")
        st.code(dns["primary"], language=None)
    with c6:
        st.markdown("**Secondary DNS**")
        st.code(dns["secondary"], language=None)

    # ── Row 3: HA ──────────────────────────────────────────────────────
    st.markdown("**High Availability (HA)**")

    if not ha["enabled"]:
        st.info("HA: Disabled (Standalone)")
    else:
        ha_cols = st.columns(5)
        fields = [
            ("Status", "✅ Enabled"),
            ("Mode", ha.get("mode", "-")),
            ("Group Name", ha.get("group_name", "-")),
            ("Device Priority", ha.get("priority", "-")),
            ("Session Pickup", ha.get("session_pickup", "-")),
        ]
        for col, (label, value) in zip(ha_cols, fields):
            with col:
                st.markdown(f"**{label}**")
                st.code(value, language=None)
