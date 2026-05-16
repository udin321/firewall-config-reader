"""
views/table_utils.py
════════════════════
Single source of truth for EVERY table in the app (FortiGate + Palo Alto).

Usage
-----
    from views.table_utils import st_table

    st_table(rows_or_df, key="unique_key_per_call")

Features
--------
* Free-text 🔎 search  — substring match across all columns (or one chosen column)
* ⬇️ CSV export button — always shown; exports the FILTERED rows
* Optional pandas row-styler passed through
* Row count caption

`key` must be unique per rendered table — use descriptive names.
`export_filename` defaults to  key + ".csv"
"""

from __future__ import annotations
import io
import pandas as pd
import streamlit as st


def st_table(
    data,
    key: str,
    title: str = "",
    style_fn=None,
    height: int | None = None,
    caption: str = "",
    export_filename: str | None = None,
) -> None:
    if isinstance(data, list):
        if not data:
            st.info("No data found.")
            return
        df = pd.DataFrame(data)
    elif isinstance(data, pd.DataFrame):
        if data.empty:
            st.info("No data found.")
            return
        df = data.copy()
    else:
        st.info("No data found.")
        return

    # drop internal _ columns for display
    display_cols = [c for c in df.columns if not c.startswith("_")]
    df_disp = df[display_cols].copy()

    if title:
        st.markdown(
            f'<div style="font-size:14px;font-weight:700;color:#e6edf3;'
            f'margin:10px 0 4px">{title}</div>',
            unsafe_allow_html=True,
        )

    cols_list = list(df_disp.columns)
    fname = export_filename or f"{key}.csv"

    # ── toolbar ────────────────────────────────────────────────
    tc1, tc2, tc3 = st.columns([4, 2, 1])
    with tc1:
        q = st.text_input(
            "🔎",
            value="",
            key=f"{key}__q",
            placeholder="Search…",
            label_visibility="collapsed",
        )
    with tc2:
        col_sel = st.selectbox(
            "col",
            ["All columns"] + cols_list,
            key=f"{key}__col",
            label_visibility="collapsed",
        )

    # ── filter ─────────────────────────────────────────────────
    filtered = df_disp.copy()
    if q.strip():
        ql = q.strip().lower()
        if col_sel == "All columns":
            mask = filtered.apply(
                lambda row: any(ql in str(v).lower() for v in row), axis=1
            )
        else:
            mask = filtered[col_sel].astype(str).str.lower().str.contains(ql, na=False)
        filtered = filtered[mask]

    n, total = len(filtered), len(df_disp)

    # ── export ─────────────────────────────────────────────────
    with tc3:
        buf = io.StringIO()
        filtered.to_csv(buf, index=False)
        st.download_button(
            "⬇️",
            buf.getvalue(),
            file_name=fname,
            mime="text/csv",
            key=f"{key}__csv",
            help=f"Export {n} row(s) → {fname}",
        )

    # ── render ─────────────────────────────────────────────────
    kw: dict = {"use_container_width": True, "hide_index": True}
    if height:
        kw["height"] = height

    if style_fn is not None and not filtered.empty:
        st.dataframe(filtered.style.apply(style_fn, axis=1), **kw)
    else:
        st.dataframe(filtered, **kw)

    parts = [f"**{n}** / **{total}** rows" if q.strip() else f"**{total}** rows"]
    if caption:
        parts.append(caption)
    st.caption("  ·  ".join(parts))
