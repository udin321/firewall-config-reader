"""
views/bgp_view.py
Renders BGP information inside the FortiGate Network tab.
"""
import streamlit as st
import pandas as pd

from parsers.fortigate_bgp import FortiGateBGPParser
from views.csv_export import render_csv_button


def render_bgp(fg):
    """Call this inside the Network tab to add a BGP section."""
    raw = getattr(fg, "raw_text", None) or getattr(fg, "config", None) or getattr(fg, "_text", None) or ""
    parser = FortiGateBGPParser(raw)
    data = parser.get_bgp_summary()

    st.markdown("---")
    st.subheader("🔄 BGP")

    if not data:
        st.info("No BGP configuration found.")
        return

    # Summary row
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Local AS",        data.get("as", "—"))
    c2.metric("Router-ID",       data.get("router-id", "—"))
    c3.metric("Neighbors",       str(len(data.get("neighbors", []))))
    c4.metric("Networks",        str(len(data.get("networks", []))))

    # Neighbors table
    neighbors = data.get("neighbors", [])
    if neighbors:
        st.markdown("**BGP Neighbors**")
        cols = ["name", "remote-as", "connect-timer", "keepalive-timer",
                "holdtime-timer", "update-source", "interface",
                "description", "password", "prefix-list-in", "prefix-list-out"]
        rows = []
        for nb in neighbors:
            rows.append({c: nb.get(c, "") for c in cols})
        df = pd.DataFrame(rows).rename(columns={
            "name": "IP/Name", "remote-as": "Remote AS",
            "connect-timer": "Connect Timer", "keepalive-timer": "Keepalive",
            "holdtime-timer": "Hold Time", "update-source": "Update Source",
            "interface": "Interface", "description": "Description",
            "prefix-list-in": "PL In", "prefix-list-out": "PL Out",
        })
        # Drop all-empty columns
        df = df.loc[:, (df != "").any(axis=0)]
        st.dataframe(df, use_container_width=True, hide_index=True)
        render_csv_button(rows, filename="bgp_neighbors.csv",
                          label="⬇️ Export BGP Neighbors CSV", key="bgp_csv")
    else:
        st.info("No BGP neighbors configured.")

    # Redistribute
    redist = data.get("redistribute", [])
    if redist:
        with st.expander("Redistribute"):
            st.dataframe(pd.DataFrame(redist), use_container_width=True, hide_index=True)

    # Networks
    networks = data.get("networks", [])
    if networks:
        with st.expander("BGP Networks"):
            st.dataframe(pd.DataFrame(networks), use_container_width=True, hide_index=True)
