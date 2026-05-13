"""
views/log_settings_view.py
FortiGate — Log Settings tab
"""

import streamlit as st
from views.csv_export import render_csv_button

# ─────────────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────────────
_LEVEL_COLOR = {
    "off": ("#8b949e", "#21262d"),
    "low": ("#3fb950", "#1a3a24"),
    "medium": ("#d29922", "#3a2a0c"),
    "high": ("#f08533", "#3a1e0c"),
    "critical": ("#f85149", "#3a0c0c"),
}


# ─────────────────────────────────────────────────────────────
# BADGE
# ─────────────────────────────────────────────────────────────
def _badge(level: str) -> str:

    l = str(level).lower()

    fg, bg = _LEVEL_COLOR.get(l, ("#8b949e", "#21262d"))

    return (
        f'<span style="background:{bg};'
        f"color:{fg};"
        f"border:1px solid {fg}55;"
        f"border-radius:12px;"
        f"padding:2px 10px;"
        f"font-size:12px;"
        f'font-weight:600">'
        f"{l.upper()}</span>"
    )


# ─────────────────────────────────────────────────────────────
# TOGGLE
# ─────────────────────────────────────────────────────────────
def _toggle(val: str) -> str:

    enabled = str(val).lower() in (
        "enable",
        "enabled",
        "yes",
        "true",
        "1",
        "all",
    )

    if enabled:

        color = "#3fb950"
        bg = "#3fb95022"
        border = "#3fb95055"
        text = "ON"

    else:

        color = "#f85149"
        bg = "#f8514922"
        border = "#f8514955"
        text = "OFF"

    return (
        f'<span style="'
        f"color:{color};"
        f"font-weight:700;"
        f"font-size:12px;"
        f"padding:3px 10px;"
        f"border-radius:10px;"
        f"background:{bg};"
        f'border:1px solid {border};">'
        f"{text}"
        f"</span>"
    )


# ─────────────────────────────────────────────────────────────
# KEY VALUE ROW
# ─────────────────────────────────────────────────────────────
def _kv_row(label: str, value: str) -> str:

    return (
        f'<div style="display:flex;'
        f"justify-content:space-between;"
        f"align-items:center;"
        f"padding:8px 2px;"
        f'border-bottom:1px solid #30363d33;">'
        f"<span>{label}</span>"
        f"{value}"
        f"</div>"
    )


# ─────────────────────────────────────────────────────────────
# TABLE
# ─────────────────────────────────────────────────────────────
def _two_col_table(rows):

    html = """
    <table style="width:100%;border-collapse:collapse;font-size:13px">
    """

    for label, val in rows:

        html += (
            f"<tr>"
            f'<td style="padding:6px 8px;'
            f"border-bottom:1px solid #30363d22;"
            f'width:65%;">{label}</td>'
            f'<td style="padding:6px 8px;'
            f'border-bottom:1px solid #30363d22;">'
            f"{_badge(val)}</td>"
            f"</tr>"
        )

    html += "</table>"

    st.markdown(html, unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# GLOBAL SETTINGS
# ─────────────────────────────────────────────────────────────
def _render_global(fg):

    st.markdown("## Global Settings")

    data = fg.parse_log_settings()

    if not data:

        st.info("No config log setting found.")

        return

    rows = [
        ("UUIDs in Traffic Log", data.get("fwpolicy_implicit_log", "disable")),
        ("Address Logging", data.get("local_in_allow", "disable")),
        ("Event Logging", data.get("local_in_deny_unicast", "disable")),
        ("Local Traffic Logging", data.get("local_in_deny_broadcast", "disable")),
        ("Memory Logging", data.get("memory", "disable")),
        ("Syslog Logging", data.get("syslog", "disable")),
        ("Resolve Hostnames", data.get("resolve_ip", "enable")),
        ("Resolve Unknown Applications", data.get("resolve_port", "enable")),
    ]

    for label, val in rows:

        st.markdown(_kv_row(label, _toggle(val)), unsafe_allow_html=True)

    export_rows = []

    for label, val in rows:

        export_rows.append(
            {
                "Setting": label,
                "Value": val,
            }
        )

    render_csv_button(
        export_rows,
        filename="fg_log_settings.csv",
        label="⬇️ Export CSV",
        key="fg_log_csv",
    )


# ─────────────────────────────────────────────────────────────
# MEMORY LOG
# ─────────────────────────────────────────────────────────────
def _render_memory(fg):

    st.markdown("## Local Logs")

    if not hasattr(fg, "get_memory_log"):

        st.error("FortiGateParser missing get_memory_log()")

        return

    mem = fg.get_memory_log()

    if not mem:

        st.info("No memory logging config found.")

        return

    rows = [
        ("Memory Logging", mem.get("status", "disable")),
        ("Disk Full Action", mem.get("diskfull", "overwrite")),
    ]

    for label, val in rows:

        if label == "Disk Full Action":

            value = f"<b>{str(val).upper()}</b>"

        else:

            value = _toggle(val)

        st.markdown(_kv_row(label, value), unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────
# THREAT WEIGHT
# ─────────────────────────────────────────────────────────────
def _render_threat_weight(fg):

    st.markdown("## 🛡️ Threat Weight")

    tw = fg.get_threat_weight()

    if not tw:

        st.info("No threat weight config found.")

        return

    st.markdown(
        _kv_row("Log Threat Weight", _toggle(tw.get("status", "enable"))),
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # ─────────────────────────
    # APPLICATION
    # ─────────────────────────
    st.markdown("### Application Protection")

    app = tw.get("application", {})

    APP_NAMES = {
        "2": "P2P",
        "6": "Proxy",
    }

    if app:

        rows = []

        for cat, lvl in app.items():

            rows.append((APP_NAMES.get(str(cat), f"Category {cat}"), lvl))

        _two_col_table(rows)

    else:

        st.info("No application threat settings found.")

    st.markdown("---")

    # ─────────────────────────
    # WEB
    # ─────────────────────────
    st.markdown("### Web Categories")

    web = tw.get("web", {})

    WEB_NAMES = {
        "1": "Drug Abuse",
        "3": "Weapons",
        "4": "Violence",
        "5": "Racism/Hate",
        "6": "Phishing/Fraud",
        "12": "Proxy Avoidance",
        "14": "Spyware/Malware",
        "26": "Nudity",
        "59": "Charitable Organizations",
        "61": "Lingerie/Swimsuit",
        "62": "Marijuana",
        "72": "Real Estate",
        "83": "Anonymizers",
        "86": "Adult Materials",
        "96": "Terrorism",
    }

    if web:

        rows = []

        for cat, lvl in web.items():

            rows.append((WEB_NAMES.get(str(cat), f"Category {cat}"), lvl))

        _two_col_table(rows)

    else:

        st.info("No web threat categories configured.")

    st.markdown("---")

    # ─────────────────────────
    # RISK VALUES
    # ─────────────────────────
    st.markdown("### ⚖️ Risk Level Values")

    lvl = tw.get("level", {})

    cols = st.columns(4)

    risks = [
        ("Low", lvl.get("low", "5")),
        ("Medium", lvl.get("medium", "10")),
        ("High", lvl.get("high", "30")),
        ("Critical", lvl.get("critical", "50")),
    ]

    for col, (name, value) in zip(cols, risks):

        col.metric(name, value)


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
def render_log_settings(fg):

    tab1, tab2, tab3 = st.tabs(
        [
            "Global Settings",
            "Local Logs",
            "Threat Weight",
        ]
    )

    with tab1:
        _render_global(fg)

    with tab2:
        _render_memory(fg)

    with tab3:
        _render_threat_weight(fg)
