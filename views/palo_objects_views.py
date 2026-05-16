"""Palo Alto Objects view - extended."""

import streamlit as st
import pandas as pd
from parsers.palo_objects import PaloObjectsParser
from views.table_utils import st_table


def _show(
    rows,
    key=None,
    empty="Not configured.",
    export_filename=None,
    style_fn=None,
    caption="",
):
    if not rows:
        st.info(empty)
        return

    st_table(
        rows,
        key=key or f"tbl_{abs(hash(str(rows)[:50]))}",
        style_fn=style_fn,
        caption=caption,
        export_filename=export_filename or f"{key or 'export'}.csv",
    )


def _badge(val, color="#2980b9"):
    return (
        f'<span style="background:{color};color:white;padding:2px 8px;'
        + f'border-radius:8px;font-size:11px;font-weight:bold">{val}</span>'
    )


def _section(title, icon=""):
    st.markdown(f"#### {icon} {title}")


def render_pa_objects(parser: PaloObjectsParser):
    st.markdown("### 📦 Objects")

    tabs = st.tabs(
        [
            "Addresses",
            "Services",
            "Tags",
            "Regions",
            "Dynamic User Groups",
            "Devices",
            "GlobalProtect HIP",
            "External Dynamic Lists",
            "Custom Objects",
            "Security Profiles",
            "Log Forwarding",
            "Authentication",
            "Decryption Profiles",
            "SD-WAN Link Mgmt",
            "Schedules",
        ]
    )

    # ── Addresses ─────────────────────────────────────────────────
    with tabs[0]:
        _section("Addresses", "📍")
        t1, t2, t3 = st.tabs(["Addresses", "Address Groups", "Application Groups"])
        with t1:
            rows = parser.get_addresses()
            if rows:
                df = pd.DataFrame(rows)
                col_f = st.selectbox(
                    "Filter by Type",
                    ["All"] + sorted(df["Type"].unique().tolist()),
                    key="addr_type",
                )
                if col_f != "All":
                    df = df[df["Type"] == col_f]
                st_table(
                    df,
                    key="pa_addresses",
                    export_filename="pa_addresses.csv",
                    caption=f"Total: {len(rows)}",
                )
            else:
                st.info("No addresses configured.")
        with t2:
            _show(
                parser.get_address_groups(),
                key="pa_address_groups",
                export_filename="pa_address_groups.csv",
            )
        with t3:
            _show(
                parser.get_application_groups(),
                key="pa_application_groups",
                export_filename="pa_application_groups.csv",
            )

    # ── Services ──────────────────────────────────────────────────
    with tabs[1]:
        _section("Services", "⚙️")
        t1, t2 = st.tabs(["Services", "Service Groups"])
        with t1:
            rows = parser.get_services()
            if rows:
                df = pd.DataFrame(rows)
                search = st.text_input("Search service name", key="svc_search")
                if search:
                    df = df[df["Name"].str.contains(search, case=False, na=False)]
                st_table(
                    df,
                    key="pa_services",
                    export_filename="pa_services.csv",
                    caption=f"Showing {len(df)} of {len(rows)} services",
                )
                st.caption(f"Showing {len(df)} of {len(rows)} services")
            else:
                st.info("No services configured.")
        with t2:
            _show(
                parser.get_service_groups(),
                key="pa_service_groups",
                export_filename="pa_service_groups.csv",
            )

    # ── Tags ──────────────────────────────────────────────────────
    with tabs[2]:
        _section("Tags", "🏷️")
        _show(parser.get_tags(), key="pa_tags", export_filename="pa_tags.csv")

    # ── Regions ───────────────────────────────────────────────────
    with tabs[3]:
        _section("Regions", "🌍")
        _show(
            parser.get_regions(),
            key="pa_regions",
            empty="No regions configured.",
            export_filename="pa_regions.csv",
        )

    # ── Dynamic User Groups ───────────────────────────────────────
    with tabs[4]:
        _section("Dynamic User Groups", "👥")
        _show(
            parser.get_dynamic_user_groups(),
            key="pa_dynamic_groups",
            empty="No dynamic user groups configured.",
            export_filename="pa_dynamic_groups.csv",
        )

    # ── Devices ───────────────────────────────────────────────────
    with tabs[5]:
        _section("Devices", "💻")
        _show(
            parser.get_devices(),
            key="pa_devices",
            empty="No device objects configured.",
            export_filename="pa_devices.csv",
        )

    # ── GlobalProtect HIP ─────────────────────────────────────────
    with tabs[6]:
        _section("GlobalProtect HIP", "🔒")
        st.markdown("##### HIP Objects")
        _show(
            parser.get_hip_objects(),
            key="pa_hip_objects",
            empty="No HIP objects configured.",
            export_filename="pa_hip_objects.csv",
        )
        st.markdown("##### HIP Profiles")
        _show(
            parser.get_hip_profiles(),
            key="pa_hip_profiles",
            empty="No HIP profiles configured.",
            export_filename="pa_hip_profiles.csv",
        )

    # ── External Dynamic Lists ────────────────────────────────────
    with tabs[7]:
        _section("External Dynamic Lists", "📋")
        rows = parser.get_external_dynamic_lists()
        if rows:
            df = pd.DataFrame(rows)
            if "Type" in df.columns:
                type_filter = st.multiselect(
                    "Filter by Type",
                    sorted(df["Type"].unique().tolist()),
                    default=sorted(df["Type"].unique().tolist()),
                    key="edl_type",
                )
                df = df[df["Type"].isin(type_filter)]
            st_table(
                df,
                key="pa_edl",
                export_filename="pa_external_dynamic_lists.csv",
                caption=f"Total custom EDLs: {len(rows)}",
            )
        else:
            st.info("No custom external dynamic lists configured.")

    # ── Custom Objects ────────────────────────────────────────────
    with tabs[8]:
        _section("Custom Objects", "🔧")
        co_tabs = st.tabs(
            ["Data Patterns", "Spyware", "Vulnerability", "URL Categories"]
        )

        with co_tabs[0]:
            st.markdown("##### Data Patterns")
            _show(
                parser.get_data_patterns(),
                key="pa_data_patterns",
                empty="No custom data patterns configured.",
                export_filename="pa_data_patterns.csv",
            )
        with co_tabs[1]:
            st.markdown("##### Custom Spyware")
            _show(
                parser.get_custom_spyware(),
                key="pa_custom_spyware",
                empty="No custom spyware objects configured.",
                export_filename="pa_custom_spyware.csv",
            )
        with co_tabs[2]:
            st.markdown("##### Custom Vulnerability")
            _show(
                parser.get_custom_vulnerability(),
                key="pa_custom_vulnerability",
                empty="No custom vulnerability objects configured.",
                export_filename="pa_custom_vulnerability.csv",
            )
        with co_tabs[3]:
            st.markdown("##### Custom URL Categories")
            _show(
                parser.get_custom_url_categories(),
                key="pa_custom_url_categories",
                empty="No custom URL categories configured.",
                export_filename="pa_custom_url_categories.csv",
            )

    # ── Security Profiles ─────────────────────────────────────────
    with tabs[9]:
        _section("Security Profiles (Custom)", "🔐")

        pg_rows = parser.get_security_profile_groups()
        if pg_rows:
            st.markdown("##### Profile Groups")
            for row in pg_rows:
                with st.expander(f"**{row['Name']}**"):
                    perm_cols = [k for k in row if k != "Name"]
                    cols = st.columns(len(perm_cols))
                    for col, perm in zip(cols, perm_cols):
                        val = row[perm]
                        bg = "#27ae60" if val != "None" else "#95a5a6"
                        col.markdown(
                            f'<div style="text-align:center;padding:6px">'
                            + f'<div style="font-size:10px;color:#666">{perm}</div>'
                            + f'<span style="background:{bg};color:white;padding:2px 8px;'
                            + f'border-radius:8px;font-size:11px">{val}</span></div>',
                            unsafe_allow_html=True,
                        )

        sp_tabs = st.tabs(
            [
                "Antivirus",
                "Anti-Spyware",
                "Vulnerability",
                "URL Filtering",
                "File Blocking",
                "WildFire",
                "Data Filtering",
                "DoS Protection",
            ]
        )

        with sp_tabs[0]:
            _show(parser.get_av_profiles(), "No custom antivirus profiles.")

        with sp_tabs[1]:
            rows = parser.get_spyware_profiles()
            if rows:
                df = pd.DataFrame(rows)

                def hl_sev(row):
                    s = str(row.get("Severity", "")).lower()
                    if "critical" in s:
                        return ["background-color:#fde8e8"] * len(row)
                    if "high" in s:
                        return ["background-color:#fef3e2"] * len(row)
                    return [""] * len(row)

                st.dataframe(
                    df.style.apply(hl_sev, axis=1),
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info("No custom anti-spyware profiles.")

        with sp_tabs[2]:
            rows = parser.get_vulnerability_profiles()
            if rows:
                df = pd.DataFrame(rows)

                def hl_vuln(row):
                    s = str(row.get("Severity", "")).lower()
                    if "critical" in s:
                        return ["background-color:#fde8e8"] * len(row)
                    if "high" in s:
                        return ["background-color:#fef3e2"] * len(row)
                    return [""] * len(row)

                st.dataframe(
                    df.style.apply(hl_vuln, axis=1),
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info("No custom vulnerability profiles.")

        with sp_tabs[3]:
            url_profiles = parser.get_url_filtering_profiles()
            if not url_profiles:
                st.info("No custom URL filtering profiles.")
            else:
                selected = st.selectbox(
                    "Select Profile",
                    [p["name"] for p in url_profiles],
                    key="url_prof_sel",
                )
                prof = next((p for p in url_profiles if p["name"] == selected), None)
                if prof:
                    st.markdown(
                        f"**Profile: `{selected}`** — {len(prof['categories'])} categories"
                    )
                    cats = prof["categories"]
                    if cats:
                        df = pd.DataFrame(cats)

                        def hl_cat(row):
                            sa = str(row.get("Site Access", "")).lower()
                            if sa == "block":
                                return ["background-color:#fdecea"] * len(row)
                            if sa == "alert":
                                return ["background-color:#fff3cd"] * len(row)
                            if sa == "allow":
                                return ["background-color:#e8f8f0"] * len(row)
                            return [""] * len(row)

                        st.dataframe(
                            df.style.apply(hl_cat, axis=1),
                            use_container_width=True,
                            hide_index=True,
                        )
                    else:
                        st.info("No category overrides configured.")

        with sp_tabs[4]:
            _show(
                parser.get_file_blocking_profiles(), "No custom file blocking profiles."
            )

        with sp_tabs[5]:
            _show(parser.get_wildfire_profiles(), "No custom WildFire profiles.")

        with sp_tabs[6]:
            _show(
                parser.get_data_filtering_profiles(),
                "No custom data filtering profiles.",
            )

        with sp_tabs[7]:
            rows = parser.get_dos_protection_profiles()
            if rows:
                st.dataframe(
                    pd.DataFrame(rows), use_container_width=True, hide_index=True
                )
            else:
                st.info("No custom DoS protection profiles.")

    # ── Log Forwarding ────────────────────────────────────────────
    with tabs[10]:
        _section("Log Forwarding", "📨")
        rows = parser.get_log_forwarding_profiles()
        if rows:
            df = pd.DataFrame(rows)
            st_table(
                df,
                key="pa_log_forwarding",
                export_filename="pa_log_forwarding.csv",
                caption=f"Total match-list entries: {len(rows)}",
            )
        else:
            st.info("No log forwarding profiles configured.")

    # ── Authentication ────────────────────────────────────────────
    with tabs[11]:
        _section("Authentication", "🔑")
        st.markdown("##### Authentication Profiles")
        _show(
            parser.get_auth_profiles(),
            key="pa_auth_profiles",
            export_filename="pa_auth_profiles.csv",
        )
        st.markdown("##### Authentication Sequences")
        _show(
            parser.get_auth_sequences(),
            key="pa_auth_sequences",
            export_filename="pa_auth_sequences.csv",
        )

    # ── Decryption Profiles ───────────────────────────────────────
    with tabs[12]:
        _section("Decryption Profiles", "🔓")
        rows = parser.get_decryption_profiles()
        if not rows:
            st.info("No decryption profiles configured.")
        else:
            for row in rows:
                with st.expander(f"**{row['Name']}**"):
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown("**SSL Forward Proxy**")
                        for k in [k for k in row if k.startswith("SFP")]:
                            val = row[k]
                            color = "#e74c3c" if val.lower() == "yes" else "#2ecc71"
                            label = k.replace("SFP - ", "")
                            st.markdown(
                                f'<div style="display:flex;justify-content:space-between;'
                                + f'padding:4px 8px;background:#f8f9fa;border-radius:6px;margin:2px 0">'
                                + f'<span style="font-size:12px">{label}</span>'
                                + f'<span style="background:{color};color:white;padding:1px 8px;'
                                + f'border-radius:8px;font-size:11px">{val}</span></div>',
                                unsafe_allow_html=True,
                            )
                    with c2:
                        st.markdown("**SSL Protocol Settings**")
                        for k in [
                            "Min TLS Version",
                            "Max TLS Version",
                            "Allow SHA1",
                            "Allow 3DES",
                            "Allow RC4",
                        ]:
                            val = row.get(k, "-")
                            st.markdown(f"**{k}:** `{val}`")
                        st.markdown("**No Decryption**")
                        st.markdown(
                            f"Block Untrusted: `{row.get('ND - Block Untrusted','-')}`"
                        )
                        st.markdown(
                            f"Block Expired: `{row.get('ND - Block Expired','-')}`"
                        )

    # ── SD-WAN Link Management ────────────────────────────────────
    with tabs[13]:
        _section("SD-WAN Link Management", "🌐")
        sdwan_tabs = st.tabs(
            ["Path Quality", "Traffic Distribution", "SaaS Quality", "Error Correction"]
        )
        with sdwan_tabs[0]:
            _show(
                parser.get_sdwan_path_quality(),
                empty="No path quality profiles configured.",
                key="pa_sdwan_path_quality",
                export_filename="pa_sdwan_path_quality.csv",
            )
        with sdwan_tabs[1]:
            rows = parser.get_sdwan_traffic_dist()
            if rows:
                df = pd.DataFrame(rows)

                def hl_dist(row):
                    dist = str(row.get("Traffic Distribution", "")).lower()
                    if "top" in dist:
                        return ["background-color:#eaf4fb"] * len(row)
                    if "weighted" in dist:
                        return ["background-color:#f3e5f5"] * len(row)
                    return [""] * len(row)

                st.dataframe(
                    df.style.apply(hl_dist, axis=1),
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.info("No traffic distribution profiles configured.")
        with sdwan_tabs[2]:
            _show(
                parser.get_sdwan_saas_quality(),
                empty="No SaaS quality profiles configured.",
                key="pa_sdwan_saas",
                export_filename="pa_sdwan_saas.csv",
            )
        with sdwan_tabs[3]:
            _show(
                parser.get_sdwan_error_correction(),
                empty="No error correction profiles configured.",
                key="pa_sdwan_error",
                export_filename="pa_sdwan_error.csv",
            )

    # ── Schedules ─────────────────────────────────────────────────
    with tabs[14]:
        _section("Schedules", "🕐")
        rows = parser.get_schedules()
        if rows:
            df = pd.DataFrame(rows)

            def hl_sched(row):
                r = str(row.get("Recurrence", "")).lower()
                if r == "one-time":
                    return ["background-color:#fef9e7"] * len(row)
                return [""] * len(row)

            st_table(
                df,
                key="pa_schedules",
                style_fn=hl_sched,
                export_filename="pa_schedules.csv",
                caption=f"Total: {len(rows)} schedules",
            )

            st.caption(f"Total: {len(rows)} schedules")
        else:
            st.info("No schedules configured.")
