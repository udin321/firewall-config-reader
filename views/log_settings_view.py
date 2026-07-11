"""
views/log_settings_view.py
FortiGate — Log & Report tab (beside System in main tabs).

Sub-tabs:
  📋 Log Settings   — Global Settings, Local Logs, GUI Preferences
  ⚖️  Threat Weight  — Application, IPS, Botnet, Malware, Packet, Web, Risk Levels

THEME FIX: every helper below previously hardcoded colors meant for dark
mode only (e.g. text color #e6edf3, a light gray, on an assumed-dark
background). When the app's light theme was active, that produced
near-invisible text on a white background. All helpers now read
st.session_state.theme and pick a contrasting palette for either mode.
"""

from __future__ import annotations
import io
import streamlit as st
import pandas as pd
from views.table_utils import st_table

# ── theme-aware palette ──────────────────────────────────────────────────────


def _palette():
    """Return a dict of colors with sufficient contrast for the active theme.

    Called fresh each render (not cached) since the user can flip the
    theme toggle at any time via st.session_state.theme.
    """
    theme = st.session_state.get("theme", "dark")
    if theme == "dark":
        return {
            "text": "#e6edf3",
            "text_dim": "#8b949e",
            "card_bg": "#161b22",
            "card_border": "#30363d",
            "accent": "#3a7bd5",
        }
    else:
        return {
            "text": "#1f2328",
            "text_dim": "#57606a",
            "card_bg": "#f6f8fa",
            "card_border": "#d0d7de",
            "accent": "#0969da",
        }


# ── helpers ────────────────────────────────────────────────────────────────────


def _on(v: str) -> bool:
    return str(v or "disable").lower() in ("enable", "on", "all", "enabled", "yes", "1")


def _toggle_row(label: str, value: str, hint: str = ""):
    pal = _palette()
    on = _on(value)
    # ON/OFF badge colors stay the same in both themes (green/red read fine
    # on both light and dark backgrounds since they carry their own fill).
    color = "#3fb950" if on else "#f85149"
    text = "ON" if on else "OFF"
    hint_html = (
        f'<div style="font-size:11px;color:{pal["text_dim"]};margin-top:1px">{hint}</div>'
        if hint
        else ""
    )
    st.markdown(
        f'<div style="display:flex;justify-content:space-between;align-items:center;'
        f"padding:10px 14px;margin:4px 0;border-radius:10px;"
        f'background:{pal["card_bg"]};border:1px solid {pal["card_border"]}">'
        f'<div><span style="color:{pal["text"]};font-size:13px;font-weight:500">{label}</span>'
        f"{hint_html}</div>"
        f'<span style="color:{color};font-weight:800;font-size:12px;padding:4px 12px;'
        f"border-radius:20px;background:{color}22;border:1px solid {color}55;"
        f'white-space:nowrap">{text}</span></div>',
        unsafe_allow_html=True,
    )


def _section(icon: str, title: str):
    pal = _palette()
    st.markdown(
        f'<div style="display:flex;align-items:center;gap:8px;'
        f'margin:20px 0 8px;border-left:3px solid {pal["accent"]};padding-left:10px">'
        f'<span style="font-size:15px">{icon}</span>'
        f'<span style="font-size:15px;font-weight:700;color:{pal["text"]}">{title}</span>'
        f"</div>",
        unsafe_allow_html=True,
    )


def _card(title: str):
    pal = _palette()
    st.markdown(
        f'<div style="font-size:11px;color:{pal["text_dim"]};font-weight:700;'
        f'text-transform:uppercase;letter-spacing:.6px;margin:14px 0 5px">{title}</div>',
        unsafe_allow_html=True,
    )


def _csv_dl(rows: list, fname: str, key: str):
    if not rows:
        return
    buf = io.StringIO()
    pd.DataFrame(rows).to_csv(buf, index=False)
    st.download_button(
        "⬇️ Export CSV", buf.getvalue(), file_name=fname, mime="text/csv", key=key
    )


# ── Threat level badge row ──────────────────────────────────────────────────────

# Foreground/background pairs for each level badge. These already carry
# their own fill colors (not relying on page background for contrast), so
# they work in both themes as-is — left unchanged.
_FG = {
    "Off": "#95a5a6",
    "Low": "#3498db",
    "Medium": "#f39c12",
    "High": "#e67e22",
    "Critical": "#e74c3c",
}
_BG = {
    "Off": "#2c3e50",
    "Low": "#1a2a3a",
    "Medium": "#3a2a0c",
    "High": "#3a1e0c",
    "Critical": "#3a0c0c",
}
_LVL = ["Off", "Low", "Medium", "High", "Critical"]


def _level_row(label: str, chosen: str):
    pal = _palette()
    badges = ""
    for lv in _LVL:
        fg, bg = _FG.get(lv, "#95a5a6"), _BG.get(lv, "#2c3e50")
        if lv == chosen:
            s = (
                f"background:{fg};color:white;border:2px solid {fg};"
                f"transform:scale(1.08);font-weight:800;box-shadow:0 0 8px {fg}55;"
            )
        else:
            s = f"background:{bg};color:{fg};border:1px solid {fg}33;opacity:0.40;font-weight:600;"
        badges += (
            f'<span style="{s}padding:3px 9px;border-radius:10px;'
            f'font-size:11px;margin:0 2px;display:inline-block">{lv}</span>'
        )
    st.markdown(
        f'<div style="display:flex;align-items:center;justify-content:space-between;'
        f"padding:8px 12px;margin:3px 0;border-radius:9px;"
        f'background:{pal["card_bg"]};border:1px solid {pal["card_border"]}">'
        f'<span style="color:{pal["text"]};font-size:13px;min-width:240px">{label}</span>'
        f'<div style="display:flex;flex-wrap:nowrap;gap:1px">{badges}</div></div>',
        unsafe_allow_html=True,
    )


# ── LOG SETTINGS sub-tab ───────────────────────────────────────────────────────


def _log_settings_tab(fg):
    log = fg.parse_log_settings()
    rows: list[dict] = []

    _section("🌐", "Global Settings")

    _card("UUIDs in Traffic Logs")
    v = log.get("uuid_traffic", "disable")
    _toggle_row(
        "Address", v, "Include policy UUIDs in traffic log (fwpolicy-implicit-log)"
    )
    rows.append({"Section": "Global", "Setting": "UUIDs / Address", "Value": v})

    _card("Log Settings")
    for label, key, hint in [
        ("Event Logging", "event_logging", "local-in-deny-unicast"),
        ("Local Traffic Logging", "local_traffic", "local-in-deny-broadcast"),
        ("Syslog Logging", "syslog", "Disabled by default"),
    ]:
        v = log.get(key, "disable")
        _toggle_row(label, v, hint)
        rows.append({"Section": "Global", "Setting": label, "Value": v})

    _section("🖥️", "GUI Preferences")
    for label, key, hint in [
        ("Resolve Hostnames", "resolve_hosts", "Enabled by default"),
        ("Resolve Unknown Applications", "resolve_apps", "Enabled by default"),
    ]:
        v = log.get(key, "enable")
        _toggle_row(label, v, hint)
        rows.append({"Section": "GUI Prefs", "Setting": label, "Value": v})

    _section("💾", "Local Logs")
    v = log.get("memory", "enable")
    _toggle_row("Memory", v, "Memory logging — enabled by default")
    rows.append({"Section": "Local Logs", "Setting": "Memory", "Value": v})

    st.markdown("<br>", unsafe_allow_html=True)
    # Searchable summary table + CSV
    with st.expander("📄 View as table / export"):
        st_table(rows, key="log_settings_tbl", export_filename="fg_log_settings.csv")


# ── THREAT WEIGHT sub-tab ──────────────────────────────────────────────────────

_WEB_ORDER = [
    "Drug Abuse",
    "Hacking",
    "Illegal or Unethical",
    "Discrimination",
    "Explicit Violence",
    "Extremist Groups",
    "Proxy Avoidance",
    "Plagiarism",
    "Child Sexual Abuse",
    "Peer-to-peer File Sharing",
    "Pornography",
    "Terrorism",
    "Phishing",
    "Spam URLs",
    "Malicious Websites",
    "Blocked URLs",
]
_MALWARE_ORDER = [
    "Virus Detected",
    "FortiNDR Virus Detected",
    "FortiSandbox Virus Detected",
    "File Blocked",
    "Blocked Command",
    "Oversized File",
    "Virus Scan Error",
    "Switch Protocol",
    "MIME Fragmented",
    "Virus File Type Executable",
    "Virus Outbreak Prevention Event",
    "Content Disarm",
    "Malware List",
    "EMS Threat Feed",
    "FortiSandbox Malicious",
    "FortiSandbox High Risk",
    "FortiSandbox Medium Risk",
]
_MALWARE_KEY = {
    "Virus Detected": "virus",
    "FortiNDR Virus Detected": "fortindr_virus",
    "FortiSandbox Virus Detected": "fortisandbox_virus",
    "File Blocked": "file_block",
    "Blocked Command": "command_block",
    "Oversized File": "oversize",
    "Virus Scan Error": "virus_scan_error",
    "Switch Protocol": "switch_proto",
    "MIME Fragmented": "mime_fragmented",
    "Virus File Type Executable": "virus_file_type_executable",
    "Virus Outbreak Prevention Event": "outbreak_prevention",
    "Content Disarm": "cdn",
    "Malware List": "malware_list",
    "EMS Threat Feed": "ems_threat_feed",
    "FortiSandbox Malicious": "fortisandbox_malicious",
    "FortiSandbox High Risk": "fortisandbox_high_risk",
    "FortiSandbox Medium Risk": "fortisandbox_medium_risk",
}


def _threat_weight_tab(fg):
    tw = fg.parse_threat_weight()
    export: list[dict] = []

    if not tw:
        st.info("ℹ️ No `config log threat-weight` block found in this configuration.")
        return

    _toggle_row("Log Threat Weight", tw.get("status", "enable"))
    export.append(
        {
            "Section": "Master",
            "Item": "Log Threat Weight",
            "Level": tw.get("status", "enable"),
        }
    )
    st.markdown("---")

    # Application Protection
    _section("📦", "Application Protection")
    for name in ["P2P", "Proxy"]:
        level = tw.get("application", {}).get(name, "Off")
        _level_row(name, level)
        export.append({"Section": "Application", "Item": name, "Level": level})

    # IPS Severity
    _section("🛡️", "Intrusion Prevention Detection Severity")
    ips = tw.get("ips_score", {})
    for item, key in [
        ("Informational", "info"),
        ("Low", "low"),
        ("Medium", "medium"),
        ("High", "high"),
        ("Critical", "critical"),
    ]:
        level = ips.get(key, "Off")
        _level_row(item, level)
        export.append({"Section": "IPS Severity", "Item": item, "Level": level})

    # Botnet
    _section("🕷️", "Botnet Communication")
    v = tw.get("botnet_connection", "Off")
    _level_row("Botnet Communication", v)
    export.append({"Section": "Botnet", "Item": "Botnet Communication", "Level": v})

    # Malware Detection
    _section("🦠", "Malware Detection")
    for item in _MALWARE_ORDER:
        level = tw.get(_MALWARE_KEY.get(item, ""), "Off")
        _level_row(item, level)
        export.append({"Section": "Malware", "Item": item, "Level": level})

    # Packet Inspection
    _section("📡", "Packet Based Inspection")
    for item, key in [
        ("Blocked Connection", "blocked_connection"),
        ("Failed Connection", "failed_connection"),
    ]:
        level = tw.get(key, "Off")
        _level_row(item, level)
        export.append({"Section": "Packet", "Item": item, "Level": level})

    # Web Activity
    _section("🌐", "Web Activity")
    web = tw.get("web", {})
    for item in _WEB_ORDER:
        level = web.get(item, "Off")
        _level_row(item, level)
        export.append({"Section": "Web Activity", "Item": item, "Level": level})

    # Risk Level Values
    _section("⚖️", "Risk Level Values")
    lmap = tw.get("level", {})
    rdefs = [
        ("Low", "#3498db", lmap.get("low", "5")),
        ("Medium", "#f39c12", lmap.get("medium", "10")),
        ("High", "#e67e22", lmap.get("high", "30")),
        ("Critical", "#e74c3c", lmap.get("critical", "50")),
    ]
    for col, (name, color, val) in zip(st.columns(4), rdefs):
        col.markdown(
            f'<div style="background:{color}22;border:2px solid {color}66;'
            f'border-radius:14px;padding:18px 12px;text-align:center">'
            f'<div style="font-size:30px;font-weight:900;color:{color}">{val}</div>'
            f'<div style="font-size:12px;color:{color};font-weight:700;'
            f'margin-top:5px;text-transform:uppercase">{name}</div></div>',
            unsafe_allow_html=True,
        )
        export.append({"Section": "Risk Levels", "Item": name, "Level": val})

    st.markdown("<br>", unsafe_allow_html=True)
    # Searchable table + CSV
    with st.expander("📄 View full threat weight as table / export"):
        st_table(export, key="tw_full_tbl", export_filename="fg_threat_weight.csv")


# ── Entry point ────────────────────────────────────────────────────────────────


def render_log_settings(fg):
    """Called from app.py as the 'Log & Report' tab."""
    pal = _palette()
    st.markdown(
        '<div style="display:flex;align-items:center;gap:10px;margin-bottom:4px">'
        '<span style="font-size:22px">📊</span>'
        f'<span style="font-size:20px;font-weight:800;color:{pal["text"]}">Log & Report</span>'
        "</div>"
        f'<div style="font-size:13px;color:{pal["text_dim"]};margin-bottom:16px">'
        "Logging and threat weight configuration — parsed from the FortiGate config file.</div>",
        unsafe_allow_html=True,
    )
    t1, t2 = st.tabs(["📋 Log Settings", "⚖️ Threat Weight"])
    with t1:
        _log_settings_tab(fg)
    with t2:
        _threat_weight_tab(fg)
