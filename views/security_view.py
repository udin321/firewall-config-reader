import streamlit as st
import pandas as pd


def _show_table(rows, empty_msg="Not configured"):
    if not rows:
        st.info(empty_msg)
        return
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def _feature_set_badge(feature_set):
    """Display a flow/proxy toggle badge."""
    is_flow = feature_set.lower() in ["flow", "flow-based", ""]
    flow_bg  = "#2980b9" if is_flow else "#bdc3c7"
    proxy_bg = "#8e44ad" if not is_flow else "#bdc3c7"
    st.markdown(
        f'<div style="display:inline-flex;border-radius:20px;overflow:hidden;margin:4px 0 10px 0">'
        f'<span style="background:{flow_bg};color:white;padding:4px 14px;font-size:12px;font-weight:bold">Flow-based</span>'
        f'<span style="background:{proxy_bg};color:white;padding:4px 14px;font-size:12px;font-weight:bold">Proxy-based</span>'
        f'</div>',
        unsafe_allow_html=True
    )


def _toggle(label, value):
    on = str(value).lower() in ["enable", "on", "1", "true"]
    color = "#2ecc71" if on else "#ccc"
    bg    = "#e8f8f0" if on else "#f5f5f5"
    text  = "ON" if on else "OFF"
    st.markdown(
        f'<div style="display:flex;align-items:center;justify-content:space-between;'
        f'background:{bg};border-radius:8px;padding:8px 14px;margin:4px 0;">'
        f'<span style="font-size:13px">{label}</span>'
        f'<span style="background:{color};color:white;padding:2px 12px;'
        f'border-radius:12px;font-size:12px;font-weight:bold">{text}</span></div>',
        unsafe_allow_html=True
    )


def _profile_cards(profiles: list, detail_fn, key_prefix: str):
    if not profiles:
        st.info("No profiles configured.")
        return
    cols = st.columns(2)
    selected_key = f"{key_prefix}_selected"
    if selected_key not in st.session_state:
        st.session_state[selected_key] = None
    for i, profile in enumerate(profiles):
        col = cols[i % 2]
        with col:
            name    = profile.get("name", "-")
            comment = profile.get("comment", "-")
            fs      = profile.get("feature_set", "flow")
            fs_icon = "🔵" if fs.lower() in ["flow","flow-based",""] else "🟣"
            fs_text = "Flow" if fs.lower() in ["flow","flow-based",""] else "Proxy"
            label   = f"{name}  {fs_icon} {fs_text}"
            if comment != "-":
                label += f"\n_{comment}_"
            if st.button(name, key=f"{key_prefix}_btn_{i}", use_container_width=True, help=comment):
                st.session_state[selected_key] = None if st.session_state[selected_key] == name else name
    selected = st.session_state.get(selected_key)
    if selected:
        profile = next((p for p in profiles if p["name"] == selected), None)
        if profile:
            st.divider()
            st.markdown(f"#### Profile: `{selected}`")
            detail_fn(profile)


def _av_detail(p):
    _feature_set_badge(p.get("feature_set", "flow"))
    st.markdown(f"**Comment:** {p.get('comment', '-')}")
    protos = p.get("protocols", [])
    if protos:
        _show_table(protos)
    else:
        st.info("No protocol scan settings configured.")


def _webfilter_detail(p):
    _feature_set_badge(p.get("feature_set", "flow"))
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("URL Filter Table", p.get("urlfilter_name", p.get("urlfilter_table", "-")))
    c2.metric("Safe Search",      p.get("safe_search", "-"))
    c3.metric("Override",         p.get("override", "-"))
    c4.metric("Options",          p.get("options", "-"))
    st.markdown(f"**Comment:** {p.get('comment', '-')}")

    # Block invalid URLs toggle
    _toggle("Block Invalid URLs", p.get("block_invalid_url", "disable"))
    st.markdown("")

    # Static URL filter table
    url_entries = p.get("urlfilter_entries", [])
    if url_entries:
        st.divider()
        st.markdown(f"##### Static URL Filter — {p.get('urlfilter_name','')} ({len(url_entries)} entries)")
        # Split allow vs block for clarity
        blocked  = [u for u in url_entries if u["Action"].lower() == "block"]
        allowed  = [u for u in url_entries if u["Action"].lower() != "block"]
        if blocked:
            st.markdown(f"**Blocked URLs ({len(blocked)})**")
            df_block = pd.DataFrame(blocked)
            def hl_block(row):
                return ["background-color:#fdecea"] * len(row)
            st.dataframe(df_block.style.apply(hl_block, axis=1), use_container_width=True, hide_index=True)
        if allowed:
            st.markdown(f"**Allowed / Exempt URLs ({len(allowed)})**")
            st.dataframe(pd.DataFrame(allowed), use_container_width=True, hide_index=True)

    # FTGD categories
    cats = p.get("categories", [])
    if cats:
        st.divider()
        blocked_cats = [c for c in cats if c["Action"].lower() == "block"]
        monitor_cats = [c for c in cats if c["Action"].lower() != "block"]
        if blocked_cats:
            st.markdown(f"**Blocked Categories ({len(blocked_cats)})**")
            st.dataframe(pd.DataFrame(blocked_cats), use_container_width=True, hide_index=True)
        if monitor_cats:
            st.markdown(f"**Monitored Categories ({len(monitor_cats)})**")
            st.dataframe(pd.DataFrame(monitor_cats), use_container_width=True, hide_index=True)
    else:
        st.info("No category filters configured.")


def _dnsfilter_detail(p):
    _feature_set_badge(p.get("feature_set", "flow"))
    c1, c2 = st.columns(2)
    c1.metric("Block Botnet", p.get("block_botnet", "-"))
    c2.metric("Safe Search",  p.get("safe_search", "-"))
    st.markdown(f"**Comment:** {p.get('comment', '-')}")
    cats = p.get("categories", [])
    if cats:
        blocked = [c for c in cats if c["Action"].lower() == "block"]
        monitor = [c for c in cats if c["Action"].lower() != "block"]
        if blocked:
            st.markdown(f"**Blocked ({len(blocked)})**")
            st.dataframe(pd.DataFrame(blocked), use_container_width=True, hide_index=True)
        if monitor:
            st.markdown(f"**Monitored ({len(monitor)})**")
            st.dataframe(pd.DataFrame(monitor), use_container_width=True, hide_index=True)
    else:
        st.info("No DNS category filters configured.")


def _appcontrol_detail(p):
    c1, c2, c3 = st.columns(3)
    c1.metric("Options",            p.get("options", "-"))
    c2.metric("Deep Inspection",    p.get("deep_inspection", "-"))
    c3.metric("Unknown App Action", p.get("unknown_action", "-"))
    st.markdown(f"**Comment:** {p.get('comment', '-')}")
    entries = p.get("entries", [])
    if entries:
        st.markdown("##### Application & Filter Overrides")
        df = pd.DataFrame(entries)
        def hl_action(row):
            action = str(row.get("Action","")).lower()
            if action == "block":
                return ["background-color:#fdecea"] * len(row)
            if action == "pass":
                return ["background-color:#e8f8f0"] * len(row)
            return [""] * len(row)
        st.dataframe(df.style.apply(hl_action, axis=1), use_container_width=True, hide_index=True)
    else:
        st.info("No entries configured.")


def _ips_detail(p):
    st.markdown(f"**Comment:** {p.get('comment', '-')}")
    st.markdown(f"**Block Malicious URL:** {p.get('block_malicious_url', '-')}")
    entries = p.get("entries", [])
    if entries:
        st.markdown("##### IPS Entries")
        _show_table(entries)
    else:
        st.info("No IPS entries configured.")


def _filefilter_detail(p):
    _feature_set_badge(p.get("feature_set", "flow"))
    st.markdown(f"**Comment:** {p.get('comment', '-')}")
    _show_table(p.get("rules", []), "No file filter rules configured.")


def _emailfilter_detail(p):
    _feature_set_badge(p.get("feature_set", "flow"))
    c1, c2 = st.columns(2)
    c1.metric("Spam Filtering", p.get("spam_filtering", "-"))
    c2.metric("BWL Table",      p.get("spam_bwl_table", "-"))
    st.markdown(f"**Comment:** {p.get('comment', '-')}")
    protos = p.get("protocols", [])
    if protos:
        st.markdown("**Protocol Settings:**")
        _show_table(protos)
    else:
        st.info("No specific protocol settings — profiles use default filtering.")


def _voip_detail(p):
    st.markdown(f"**Comment:** {p.get('comment', '-')}")
    sip  = p.get("sip", {})
    sccp = p.get("sccp", {})
    if sip:
        st.markdown("**SIP:**")
        c1, c2, c3 = st.columns(3)
        c1.metric("Status", sip.get("status", "-"))
        c2.metric("RTP",    sip.get("rtp", "-"))
        c3.metric("Port",   sip.get("port", "-"))
    if sccp:
        st.markdown("**SCCP:**")
        c1, c2 = st.columns(2)
        c1.metric("Status", sccp.get("status", "-"))
        c2.metric("Port",   sccp.get("port", "-"))
    if not sip and not sccp:
        st.info("No SIP/SCCP configuration found.")


def _waf_detail(p):
    st.markdown(f"**Comment:** {p.get('comment', '-')}")
    sigs = p.get("signatures", [])
    if sigs:
        st.markdown("**Signature Classes**")
        df_sigs = pd.DataFrame(sigs)
        def colour_sig(row):
            if str(row.get("Status","")).lower() == "enable" and str(row.get("Action","")).lower() == "block":
                return ["background-color:#fde8e8"] * len(row)
            elif str(row.get("Status","")).lower() == "enable":
                return ["background-color:#fff3cd"] * len(row)
            return ["color:#aaa"] * len(row)
        st.dataframe(df_sigs.style.apply(colour_sig, axis=1), use_container_width=True, hide_index=True)
    disabled = p.get("disabled_sigs", "-")
    if disabled and disabled != "-":
        st.markdown(f"**Disabled Signatures:** `{disabled}`")
    constraints = p.get("constraints", [])
    if constraints:
        st.markdown("**Constraints**")
        _show_table(constraints)


def _ssl_detail(p):
    c1, c2 = st.columns(2)
    c1.metric("CA Certificate",    p.get("ca_cert", "-"))
    c2.metric("Untrusted CA Cert", p.get("untrusted_cert", "-"))
    st.markdown(f"**Comment:** {p.get('comment', '-')}")
    _show_table(p.get("protocols", []), "No protocol configurations found.")


def render_security(parser):
    st.subheader("Security Profiles")

    (
        tab_av, tab_wf, tab_dns, tab_app,
        tab_ips, tab_ff, tab_ef, tab_voip,
        tab_waf, tab_ssl, tab_wro, tab_wpo
    ) = st.tabs([
        "Antivirus", "Web Filter", "DNS Filter", "App Control",
        "IPS", "File Filter", "Email Filter", "VoIP",
        "WAF", "SSL Inspection", "Web Rating Overrides", "Web Profile Overrides"
    ])

    with tab_av:
        st.markdown("#### Antivirus Profiles")
        _profile_cards(parser.parse_antivirus(), _av_detail, "av")

    with tab_wf:
        st.markdown("#### Web Filter Profiles")
        _profile_cards(parser.parse_webfilter(), _webfilter_detail, "wf")

    with tab_dns:
        st.markdown("#### DNS Filter Profiles")
        _profile_cards(parser.parse_dnsfilter(), _dnsfilter_detail, "dns")

    with tab_app:
        st.markdown("#### Application Control Profiles")
        _profile_cards(parser.parse_appcontrol(), _appcontrol_detail, "app")

    with tab_ips:
        st.markdown("#### IPS Sensor Profiles")
        _profile_cards(parser.parse_ips(), _ips_detail, "ips")

    with tab_ff:
        st.markdown("#### File Filter Profiles")
        _profile_cards(parser.parse_filefilter(), _filefilter_detail, "ff")

    with tab_ef:
        st.markdown("#### Email Filter Profiles")
        _profile_cards(parser.parse_emailfilter(), _emailfilter_detail, "ef")

    with tab_voip:
        st.markdown("#### VoIP Profiles")
        _profile_cards(parser.parse_voip(), _voip_detail, "voip")

    with tab_waf:
        st.markdown("#### Web Application Firewall Profiles")
        _profile_cards(parser.parse_waf(), _waf_detail, "waf")

    with tab_ssl:
        st.markdown("#### SSL Inspection Profiles")
        _profile_cards(parser.parse_ssl_inspection(), _ssl_detail, "ssl")

    with tab_wro:
        st.markdown("#### Web Rating Overrides")
        rows = parser.parse_web_rating_override()
        if not rows:
            st.info("No web rating overrides configured.")
        else:
            all_cats = sorted(set(r["Category Name"] for r in rows))
            selected = st.multiselect("Filter by Category", all_cats, default=all_cats, key="wro_filter")
            filtered = [r for r in rows if r["Category Name"] in selected]
            _show_table(filtered, "No entries match filter.")

    with tab_wpo:
        st.markdown("#### Web Profile Overrides")
        _show_table(parser.parse_web_profile_override(), "No web profile overrides configured.")
