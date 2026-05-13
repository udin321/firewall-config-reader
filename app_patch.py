"""
app_patch.py  –  Instructions to patch app.py
==============================================

This file is NOT imported.  It explains what to change in app.py and shows
the exact replacement snippets.

─────────────────────────────────────────────────────────────
CHANGE 1 – FortiGate tab list (around line 944)
─────────────────────────────────────────────────────────────
FIND:
    main_tabs = st.tabs(
        [
            "🏠 Summary",
            "🔌 Interfaces",
            "🌐 Network",
            "📋 Policy & Objects",
            "🔒 Security",
            "🔑 VPN",
            "👤 User & Auth",
            "📡 WiFi & Switch",
            "💻 System",
        ]
    )

REPLACE WITH:
    main_tabs = st.tabs(
        [
            "🏠 Summary",
            "🔌 Interfaces",
            "🌐 Network",
            "📋 Policy & Objects",
            "🔍 Policy Lookup",          # NEW
            "🔒 Security",
            "🔑 VPN",
            "👤 User & Auth",
            "📡 WiFi & Switch",
            "💻 System",
            "📊 Log Settings",            # NEW
        ]
    )

─────────────────────────────────────────────────────────────
CHANGE 2 – FortiGate imports (around line 931)
─────────────────────────────────────────────────────────────
ADD these imports after the existing ones:
    from views.policy_lookup_view import render_policy_lookup
    from views.log_settings_view  import render_log_settings
    from views.bgp_view           import render_bgp

─────────────────────────────────────────────────────────────
CHANGE 3 – FortiGate tab rendering (after the "with main_tabs[8]:" block)
─────────────────────────────────────────────────────────────
FIND:
    with main_tabs[0]:
        render_summary(fg)
    with main_tabs[1]:
        render_interfaces(fg)
    with main_tabs[2]:
        render_network(fg)
    with main_tabs[3]:
        render_policy_objects(fg)
    with main_tabs[4]:
        render_security(fg)
    with main_tabs[5]:
        render_vpn(fg)
    with main_tabs[6]:
        render_user(fg)
    with main_tabs[7]:
        render_wifi(fg)
    with main_tabs[8]:
        render_system(fg)

REPLACE WITH:
    with main_tabs[0]:
        render_summary(fg)
    with main_tabs[1]:
        render_interfaces(fg)
    with main_tabs[2]:
        render_network(fg)
        render_bgp(fg)               # BGP section appended inside Network tab
    with main_tabs[3]:
        render_policy_objects(fg)
    with main_tabs[4]:
        render_policy_lookup(fg)     # NEW Policy Lookup tab
    with main_tabs[5]:
        render_security(fg)
    with main_tabs[6]:
        render_vpn(fg)
    with main_tabs[7]:
        render_user(fg)
    with main_tabs[8]:
        render_wifi(fg)
    with main_tabs[9]:
        render_system(fg)
    with main_tabs[10]:
        render_log_settings(fg)      # NEW Log Settings tab

─────────────────────────────────────────────────────────────
CHANGE 4 – FortiGate sidebar nav (around line 614)
─────────────────────────────────────────────────────────────
ADD these two entries to the FortiGate nav_items list:
    ("🔍", "Policy Lookup"),
    ("📊", "Log Settings"),

─────────────────────────────────────────────────────────────
CHANGE 5 – Palo Alto HA view (in views/palo_device_views.py)
─────────────────────────────────────────────────────────────
Wherever render_ha() / ha_info is rendered, replace with:

    from parsers.palo_ha_patch      import PaloHAPatchMixin
    from views.palo_ha_view_patch   import render_ha_patched

    # Patch the parser to use the fixed HA method
    PaloDashboardParser.__bases__ = PaloDashboardParser.__bases__  # no change needed if already inheriting PaloAltoParser
    # OR, simpler: just call:
    ha_data = PaloHAPatchMixin.get_ha_info_patched(parser_instance)
    render_ha_patched(ha_data)

─────────────────────────────────────────────────────────────
CHANGE 6 – CSV export for Palo Alto tables
─────────────────────────────────────────────────────────────
In every Palo Alto view file (palo_policies_views.py, palo_objects_views.py,
palo_network_views.py, palo_device_views.py) add:

    from views.csv_export import render_csv_button

Then after every st.dataframe(...) call add:
    render_csv_button(rows_or_df, filename="<descriptive_name>.csv")
"""
