import streamlit as st
import pandas as pd


def render_interfaces(rows: list, vendor: str):

    st.subheader(f"Interface Configuration — {vendor}")

    if not isinstance(rows, list):
        st.error(f"Invalid interface data type: {type(rows)}")
        return

    if len(rows) == 0:
        st.warning("No interface data found.")
        return

    # ensure list of dicts
    if isinstance(rows[0], str):
        st.error("Interface data is not structured (string list detected)")
        return

    df = pd.DataFrame(rows)

    # Colour coding
    def style_row(row):
        name = str(row.get("Name", ""))
        status = str(row.get("Status", "Enable")).lower()
        itype = str(row.get("Type", "")).lower()

        # Zone header row
        if itype == "zone":
            return ["background-color:#dfe6e9;font-weight:bold;color:#2c3e50"] * len(
                row
            )
        # Disabled interface
        if status == "disable":
            return [
                "background-color:#fdecea;color:#999;text-decoration:line-through"
            ] * len(row)
        # Hardware switch
        if itype == "hardwareswitch":
            return ["background-color:#eaf4fb"] * len(row)
        # VLAN (indented child)
        if "\u2517" in name or "\u00a0" in name:
            return ["background-color:#f8f9fa"] * len(row)
        return [""] * len(row)

    st.markdown(
        """
    <style>
    .legend-box {display:inline-block;width:14px;height:14px;border-radius:3px;margin-right:5px;vertical-align:middle}
    </style>
    <div style="margin-bottom:12px;display:flex;gap:20px;flex-wrap:wrap">
        <span><span class="legend-box" style="background:#dfe6e9"></span>Zone</span>
        <span><span class="legend-box" style="background:#eaf4fb"></span>Hardware Switch</span>
        <span><span class="legend-box" style="background:#f8f9fa"></span>Sub-interface / VLAN</span>
        <span><span class="legend-box" style="background:#fdecea"></span>Disabled</span>
    </div>
    """,
        unsafe_allow_html=True,
    )

    st.dataframe(
        df.style.apply(style_row, axis=1),
        use_container_width=True,
        hide_index=True,
    )
    total = len([r for r in rows if r.get("Type", "").lower() != "zone"])
    enabled = len(
        [
            r
            for r in rows
            if str(r.get("Status", "")).lower() == "enable"
            and r.get("Type", "").lower() != "zone"
        ]
    )
    disabled = total - enabled
    zones = len([r for r in rows if r.get("Type", "").lower() == "zone"])
    st.caption(
        f"Total: {total} interfaces | ✅ {enabled} enabled | 🔴 {disabled} disabled | 📦 {zones} zones"
    )
