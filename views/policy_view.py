import streamlit as st
import pandas as pd


def render_policy_table(rows: list[dict], vendor: str):
    st.subheader(f"📋 Firewall Policies — {vendor}")
    if not rows:
        st.info(
            "Policy parsing not yet implemented for this vendor, or no policies found."
        )
        return
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True)
