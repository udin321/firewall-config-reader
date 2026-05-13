"""
views/palo_ha_view_patch.py
Drop-in replacement / patch for the Palo Alto HA section renderer.

Usage in palo_device_views.py (or wherever HA is rendered):
    from views.palo_ha_view_patch import render_ha_patched
    render_ha_patched(ha_data)
"""
import streamlit as st


def _toggle(val: str) -> str:
    on = str(val).lower() in ("yes", "enable", "true", "1", "enabled")
    c, label = ("#3fb950", "✅ Enabled") if on else ("#f85149", "❌ Disabled")
    return f'<span style="color:{c};font-weight:600">{label}</span>'


def _kv(label: str, value: str):
    st.markdown(
        f'<div style="display:flex;justify-content:space-between;padding:5px 0;'
        f'border-bottom:1px solid #30363d22;font-size:13px">'
        f'<span>{label}</span><b>{value}</b></div>',
        unsafe_allow_html=True,
    )


def render_ha_patched(ha: dict):
    """Render HA data returned by PaloHAPatchMixin.get_ha_info_patched()."""
    if not ha or not ha.get("enabled"):
        st.info("ℹ️ High Availability is **disabled** on this device.")
        return

    st.success(f"✅ HA Mode: **{ha.get('mode','active-passive').upper()}**  |  Group ID: **{ha.get('group_id','1')}**")

    # ── General / Election ─────────────────────────────────────────────────
    with st.expander("⚙️ General / Election Settings", expanded=True):
        elec = ha.get("election", {})
        c1, c2 = st.columns(2)
        with c1:
            _kv("Device Priority",    elec.get("device_priority", "100"))
            _kv("Preemptive",         elec.get("preemptive", "no").upper())
        with c2:
            _kv("Heartbeat Backup",   elec.get("heartbeat_backup", "no").upper())
            _kv("Timer Profile",      elec.get("timers_profile", "Recommended"))

    # ── Active/Passive ─────────────────────────────────────────────────────
    ap = ha.get("active_passive", {})
    if ap:
        with st.expander("🔗 Active / Passive Settings", expanded=True):
            c1, c2 = st.columns(2)
            with c1:
                pls = ap.get("passive_link_state", "shutdown")
                pls_color = "#d29922" if pls.lower() == "auto" else "#3fb950"
                st.markdown(
                    f'<div style="padding:5px 0;font-size:13px">Passive Link State: '
                    f'<span style="color:{pls_color};font-weight:600">{pls.upper()}</span></div>',
                    unsafe_allow_html=True,
                )
            with c2:
                _kv("Monitor Fail Hold-Down (min)",
                    ap.get("monitor_fail_hold_down_time", "1"))

    # ── HA Interfaces ──────────────────────────────────────────────────────
    intf_keys = [k for k in ("ha1","ha1-backup","ha2","ha2-backup") if k in ha]
    if intf_keys:
        with st.expander("🔌 HA Interfaces"):
            for k in intf_keys:
                d = ha[k]
                st.markdown(f"**{k.upper()}**")
                c1, c2, c3 = st.columns(3)
                c1.metric("Port",       d.get("port","—"))
                c2.metric("IP Address", d.get("ip_address","—"))
                c3.metric("Encryption", d.get("encryption","no").upper())

    # ── Link Monitoring ────────────────────────────────────────────────────
    lmon = ha.get("link_monitoring", {})
    with st.expander("📡 Link Monitoring", expanded=True):
        enabled = lmon.get("enabled", "yes")
        st.markdown(
            f'Link Monitoring: {_toggle(enabled)} '
            f'<span style="font-size:12px;color:#8b949e">(PAN-OS default: Enabled)</span>',
            unsafe_allow_html=True,
        )
        _kv("Failure Condition", lmon.get("failure_condition","any").upper())
        groups = lmon.get("groups", [])
        if groups:
            for g in groups:
                st.caption(
                    f"Group: {g.get('name','')} | "
                    f"Enabled: {g.get('enabled','yes')} | "
                    f"Interfaces: {', '.join(g.get('interfaces',[])) or '—'}"
                )
        else:
            st.caption("No link monitoring groups configured.")

    # ── Path Monitoring ────────────────────────────────────────────────────
    pmon = ha.get("path_monitoring", {})
    with st.expander("🛤️ Path Monitoring", expanded=True):
        enabled = pmon.get("enabled", "yes")
        st.markdown(
            f'Path Monitoring: {_toggle(enabled)} '
            f'<span style="font-size:12px;color:#8b949e">(PAN-OS default: Enabled)</span>',
            unsafe_allow_html=True,
        )
        _kv("Failure Condition", pmon.get("failure_condition","any").upper())
        groups = pmon.get("groups", [])
        if groups:
            for g in groups:
                st.caption(
                    f"Group: {g.get('name','')} | "
                    f"Ping Interval: {g.get('ping_interval','200')} ms | "
                    f"Destinations: {', '.join(g.get('destinations',[])) or '—'}"
                )
        else:
            st.caption("No path monitoring groups configured.")
