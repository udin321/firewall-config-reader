"""
views/csv_export.py
Reusable CSV-export helper for any pandas DataFrame or list-of-dicts.
Call render_csv_button() right below any st.dataframe() call.
"""
import io
import pandas as pd
import streamlit as st


def render_csv_button(
    data,
    filename: str = "export.csv",
    label: str = "⬇️ Export CSV",
    key: str | None = None,
):
    """
    Render a single Streamlit download button that exports *data* as CSV.

    Parameters
    ----------
    data      : list[dict] | pd.DataFrame
    filename  : str   suggested download filename
    label     : str   button label
    key       : str   optional unique Streamlit key
    """
    if isinstance(data, list):
        if not data:
            return
        df = pd.DataFrame(data)
    elif isinstance(data, pd.DataFrame):
        df = data
    else:
        return

    buf = io.StringIO()
    df.to_csv(buf, index=False)
    st.download_button(
        label=label,
        data=buf.getvalue(),
        file_name=filename,
        mime="text/csv",
        key=key,
    )
