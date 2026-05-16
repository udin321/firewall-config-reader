"""views/interface_view.py — FortiGate & Palo Alto interface tables."""

import streamlit as st
import pandas as pd
from views.table_utils import st_table


def render_interface_table(rows: list, vendor: str):
    st.subheader(f"Interface Configuration — {vendor}")
    if not rows:
        st.warning("No interface data found.")
        return

    df = pd.DataFrame(rows)

    def _style(row):
        name = str(row.get("Name", ""))
        status = str(row.get("Status", "Enable")).lower()
        itype = str(row.get("Type", "")).lower()
        if itype == "zone":
            return ["background-color:#dfe6e9;font-weight:bold;color:#2c3e50"] * len(
                row
            )
        if status == "disable":
            return [
                "background-color:#fdecea;color:#999;text-decoration:line-through"
            ] * len(row)
        if itype == "hardwareswitch":
            return ["background-color:#eaf4fb"] * len(row)
        if "\u2517" in name or "\u00a0" in name:
            return ["background-color:#f8f9fa"] * len(row)
        return [""] * len(row)

    # ── legend — uses st.columns so no raw HTML colour boxes needed ───────────
    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(
        '<div style="background:#dfe6e9;border-radius:6px;padding:5px 10px;'
        'font-size:12px;font-weight:600;color:#2c3e50;text-align:center">📦 Zone</div>',
        unsafe_allow_html=True,
    )
    c2.markdown(
        '<div style="background:#eaf4fb;border-radius:6px;padding:5px 10px;'
        'font-size:12px;color:#1a6e96;text-align:center">🔌 Hardware Switch</div>',
        unsafe_allow_html=True,
    )
    c3.markdown(
        '<div style="background:#f8f9fa;border-radius:6px;padding:5px 10px;'
        'font-size:12px;color:#555;text-align:center">↳ Sub-interface / VLAN</div>',
        unsafe_allow_html=True,
    )
    c4.markdown(
        '<div style="background:#fdecea;border-radius:6px;padding:5px 10px;'
        'font-size:12px;color:#c0392b;text-align:center">🔴 Disabled</div>',
        unsafe_allow_html=True,
    )
    st.markdown("<div style='margin-bottom:8px'></div>", unsafe_allow_html=True)

    total = len([r for r in rows if r.get("Type", "").lower() != "zone"])
    enabled = len(
        [
            r
            for r in rows
            if str(r.get("Status", "")).lower() == "enable"
            and r.get("Type", "").lower() != "zone"
        ]
    )
    zones = len([r for r in rows if r.get("Type", "").lower() == "zone"])
    vkey = vendor.lower().replace(" ", "_")

    st_table(
        df,
        key=f"iface_{vkey}",
        style_fn=_style,
        caption=f"✅ {enabled} enabled · 🔴 {total-enabled} disabled · 📦 {zones} zones",
        export_filename=f"{vkey}_interfaces.csv",
    )


def render_interfaces(rows: list, vendor: str):
    render_interface_table(rows, vendor)
