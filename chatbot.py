"""
chatbot.py — Floating AI chatbox for the Firewall Config Reader

Responsibilities:
1. Build a compact, structured text summary of a large raw config
   (so we don't ship multi-MB files to the LLM on every question), and
   cross-check whether the config's actual CONTENT matches the vendor
   the app assumed from the file extension.
2. Call the Google Gemini API with that summary + chat history + new
   question, telling it explicitly which vendor's syntax it's looking at
   (and flagging any extension/content mismatch) so it reasons correctly
   about FortiGate CLI syntax vs. Palo Alto XML rather than guessing.
3. Render a floating chat button (bottom-right) with three size modes —
   compact, expanded, and a near-fullscreen overlay — styled with a
   theme-aware palette that follows the app's own light/dark toggle.

This module is intentionally decoupled from the vendor-specific parser
classes (PaloPoliciesParser, FortiGateParser, etc.) so it works purely
off the raw decoded config text already stored in
st.session_state.raw_content. If/when you want it to use your richer
parsed objects instead of regex extraction, swap out
`build_config_summary()` internals only — nothing else needs to change.

NOTE ON "POP OUT TO NEW WINDOW": a literal new browser tab would NOT
share this app's session state — Streamlit treats each browser tab as
its own independent session, so a real new tab would show an empty chat
with no config loaded (confirmed against Streamlit's own session model
docs; this is a framework limitation, not something fixable with extra
code). The "overlay" size mode is the honest substitute — same session,
same chat history, just a much larger in-page view.

NOTE ON DATA PRIVACY: Gemini's free tier may use submitted prompts to
improve Google's products, and human reviewers can process inputs and
outputs (see https://ai.google.dev/gemini-api/terms). Since this app
sends firewall configuration data to the API, consider whether that's
acceptable for your use case — if you're handling real customer configs
rather than test/personal data, look into Gemini's paid tier (different
data-use terms) or another provider before relying on this in production.
"""

from __future__ import annotations

import os
import re
import streamlit as st

try:
    from google import genai
    from google.genai import types as genai_types
except ImportError:
    genai = None
    genai_types = None


MODEL = "gemini-2.5-flash"

# Hard ceiling on how much summarized text we ever send per request.
MAX_SUMMARY_CHARS = 60_000

# Message-area heights (the scrollable region inside the panel). Panel
# heights in SIZE_PRESETS below are DERIVED from these via _PANEL_OVERHEAD,
# rather than chosen independently — picking both numbers separately is
# exactly what caused the chat input to get clipped or pushed off-panel
# in compact/overlay modes before: the message area's fixed height plus
# the header/controls/input could exceed the panel's total fixed height
# with no room left, so something had to get cut off.
#
# IMPORTANT: st.container(height=N) is a HARD pixel value that cannot
# shrink — it is not a flexible/flex-basis size. If the real rendered
# height of the header + controls + input ever exceeds what
# _PANEL_OVERHEAD assumes (e.g. due to font rendering differences, a
# vendor-mismatch warning banner, or browser chrome variations), the
# message area still claims its full fixed height regardless, and the
# input gets pushed outside the panel's bounds — this is what was still
# happening in overlay mode even after the first attempt at this fix.
# The margin below is intentionally generous (more than double the
# original estimate) specifically to make that failure mode very hard to
# hit again, rather than continuing to fine-tune a number that has
# already proven wrong twice.
_MESSAGE_AREA_HEIGHTS = {"compact": 200, "expanded": 340, "overlay": 400}
_PANEL_OVERHEAD = 260

# Panel size presets (CSS values), selected via the size-toggle buttons.
SIZE_PRESETS = {
    size: {
        "width": w,
        "height": f"{_MESSAGE_AREA_HEIGHTS[size] + _PANEL_OVERHEAD}px",
    }
    for size, w in {
        "compact": "340px",
        "expanded": "460px",
        "overlay": "min(900px, 92vw)",
    }.items()
}
# Overlay also needs a viewport-relative cap so it never exceeds the
# screen on short laptop displays — apply that as a CSS min() on top of
# the computed pixel height rather than a flat px value.
SIZE_PRESETS["overlay"][
    "height"
] = f"min({_MESSAGE_AREA_HEIGHTS['overlay'] + _PANEL_OVERHEAD}px, 82vh)"


# ──────────────────────────────────────────────────────────────────────────
# 1. Vendor content detection (sanity-check against the claimed vendor)
# ──────────────────────────────────────────────────────────────────────────


def detect_vendor_from_content(raw_text: str) -> str | None:
    """Best-effort detection of which vendor a config's CONTENT looks like,
    independent of filename/extension. Returns "Palo Alto", "FortiGate",
    or None if neither pattern is recognizable (or signals conflict).

    Palo Alto PAN-OS exports are XML: they start with an XML declaration
    or <config> root tag and are full of <entry name="..."> elements.
    FortiGate FortiOS exports are line-oriented CLI syntax: blocks of
    `config <section>` ... `end`, with `edit "<name>"` / `set ...` / `next`
    inside. The two are structurally unmistakable even from a small sample,
    so this only needs to look at the first few KB — cheap even on
    multi-MB files, and avoids false positives from, say, a comment
    embedded deep in an otherwise-correct file.
    """
    sample = raw_text[:5000]

    looks_xml = bool(re.search(r"<\?xml|<config[\s>]", sample, re.IGNORECASE)) or bool(
        re.search(r'<entry\s+name="', sample)
    )

    looks_fortios = bool(
        re.search(
            r"^\s*config\s+(system|firewall|router|log|user|vpn|wireless)",
            sample,
            re.IGNORECASE | re.MULTILINE,
        )
    )

    if looks_xml and not looks_fortios:
        return "Palo Alto"
    if looks_fortios and not looks_xml:
        return "FortiGate"
    return None  # ambiguous, contradictory, or unrecognized — don't guess


# ──────────────────────────────────────────────────────────────────────────
# 2. Config summarization (raw text -> compact structured text)
# ──────────────────────────────────────────────────────────────────────────


def _fmt_rows(rows: list, max_rows: int = 20) -> list[str]:
    """Render a list of dicts (the standard return shape used by nearly every
    parser method here) as compact 'key=value | key=value' lines, capped to
    max_rows with a note about how many were omitted."""
    out = []
    sample = rows[:max_rows]
    for row in sample:
        if isinstance(row, dict):
            parts = [f"{k}={v}" for k, v in row.items() if not str(k).startswith("_")]
            out.append("  - " + " | ".join(parts))
        else:
            out.append(f"  - {row}")
    if len(rows) > max_rows:
        out.append(f"  ... and {len(rows) - max_rows} more entries omitted for brevity")
    return out


def _section(title: str, rows: list, max_rows: int = 20) -> list[str]:
    """One named section: a header with the count, then up to max_rows
    formatted entries. Returns [] if rows is empty, so sections that don't
    apply to a given config disappear from the summary instead of adding
    '0 entries' noise."""
    if not rows:
        return []
    return [f"\n[{title}] — {len(rows)} entries", *_fmt_rows(rows, max_rows)]


def _build_fortigate_summary_from_parser(text: str) -> str:
    """Build the config summary by calling the REAL FortiGateParser and its
    mixins (SecurityProfileMixin, VPNParserMixin, UserParserMixin,
    WiFiParserMixin, SystemParserMixin) rather than re-deriving extraction
    logic independently in this file.

    This is the fix for the AI being unable to answer about static routes,
    IPsec tunnels, security profiles, VPN settings, etc. — the previous
    version of this function only understood `firewall policy` and a
    couple of other sections via its own simplified regex pass; everything
    else (router static, vpn ipsec phase1/2-interface, antivirus profile,
    webfilter profile, and so on) was invisible to it even though the
    actual parsers already handle all of this correctly. Calling the real
    methods means this summary's coverage automatically tracks whatever
    the parser stack supports.
    """
    from parsers.fortigate import FortiGateParser

    fg = FortiGateParser(text)
    out = ["=== FortiGate Config Summary (via parser) ==="]

    out.append(f"\nHostname: {fg.get_hostname()}")
    out.append(f"Firmware: {fg.get_firmware_version()}")
    out.append(f"WAN IP: {fg.get_wan_ip()}")

    ha = fg.get_ha_config()
    if ha.get("enabled"):
        out.append(
            f"\nHA: enabled, mode={ha.get('mode')}, group={ha.get('group_name')}, "
            f"priority={ha.get('priority')}"
        )
    else:
        out.append("\nHA: standalone (not configured)")

    # Network
    out += _section("Interfaces", fg.parse_interfaces(), max_rows=30)
    out += _section("Static Routes", fg.parse_static_routes())
    out += _section("Policy Routes", fg.parse_policy_routes())
    sdwan = fg.parse_sdwan()
    out += _section("SD-WAN", [sdwan] if sdwan else [])
    ospf = fg.parse_ospf()
    out += _section("OSPF", [ospf] if ospf else [])
    bgp = fg.parse_bgp()
    out += _section("BGP", [bgp] if bgp else [])

    # Firewall / Policy & Objects
    out += _section("Firewall Policies", fg.parse_policies(), max_rows=30)
    out += _section("Proxy Policies", fg.parse_proxy_policy())
    addrs = fg.parse_addresses()
    for key, label in [
        ("subnet", "Address Objects (Subnet)"),
        ("fqdn", "Address Objects (FQDN)"),
        ("iprange", "Address Objects (IP Range)"),
        ("groups", "Address Groups"),
    ]:
        out += _section(label, addrs.get(key, []))
    svc = fg.parse_services()
    out += _section("Services", svc.get("services", []), max_rows=25)
    out += _section("Virtual IPs (VIP/NAT)", fg.parse_vip())
    out += _section("IP Pools", fg.parse_ip_pools())

    # VPN (the section most commonly asked about and previously invisible)
    out += _section("IPsec Phase1 (VPN Tunnels)", fg.parse_ipsec_phase1())
    out += _section("IPsec Phase2", fg.parse_ipsec_phase2())
    out += _section("SSL VPN Portals", fg.parse_ssl_portals())
    ssl_settings = fg.parse_ssl_settings()
    if ssl_settings:
        out += _section("SSL VPN Settings", [ssl_settings])

    # Security profiles
    out += _section("Antivirus Profiles", fg.parse_antivirus())
    out += _section("Web Filter Profiles", fg.parse_webfilter())
    out += _section("DNS Filter Profiles", fg.parse_dnsfilter())
    out += _section("Application Control", fg.parse_appcontrol())
    out += _section("IPS Sensors", fg.parse_ips())
    out += _section("SSL Inspection Profiles", fg.parse_ssl_inspection())

    # Users / Auth
    out += _section("Local Users", fg.parse_user_local())
    out += _section("User Groups", fg.parse_user_groups())
    out += _section("LDAP Servers", fg.parse_ldap())
    out += _section("RADIUS Servers", fg.parse_radius())

    # System
    out += _section("Administrators", fg.parse_admins())
    sysinfo = fg.parse_system_settings()
    if sysinfo:
        out.append(
            f"\nSystem hostname/timezone: {sysinfo.get('hostname')} / TZ {sysinfo.get('timezone')}"
        )

    # WiFi / Switch
    out += _section("FortiAP Profiles", fg.parse_fortiap_profiles())
    out += _section("SSIDs", fg.parse_ssids())
    out += _section("Managed Switches", fg.parse_managed_switches())

    return "\n".join(out)


def _build_paloalto_summary_from_parser(root) -> str:
    """Build the config summary by calling the REAL Palo Alto parser
    classes (PaloDashboardParser, PaloPoliciesParser, PaloObjectsParser,
    PaloNetworkParser, PaloDeviceParser) instead of a generic XML
    entry-name scan. Same rationale as the FortiGate version above: the
    old approach only counted <entry name="..."> tags and couldn't tell
    a security rule from an address object from a zone.
    """
    from parsers.palo_dashboard import PaloDashboardParser
    from parsers.palo_policies import PaloPoliciesParser
    from parsers.palo_objects import PaloObjectsParser
    from parsers.palo_network import PaloNetworkParser
    from parsers.palo_device import PaloDeviceParser

    dash = PaloDashboardParser(root)
    pol = PaloPoliciesParser(root)
    obj = PaloObjectsParser(root)
    net = PaloNetworkParser(root)
    dev = PaloDeviceParser(root)

    out = ["=== Palo Alto Config Summary (via parser) ==="]

    dd = dash.get_dashboard_data()
    sysinfo = dd.get("system", {})
    out.append(f"\nHostname: {sysinfo.get('hostname', 'Unknown')}")
    out.append(f"Software Version: {sysinfo.get('software_version', '-')}")
    out.append(f"Mgmt IP: {sysinfo.get('ip_address', '-')}")

    ha = dd.get("ha", {})
    if ha.get("enabled"):
        out.append(f"\nHA: enabled, mode={ha.get('mode')}, peer={ha.get('peer_ip')}")
    else:
        out.append("\nHA: not configured")

    # Policies
    out += _section("Security Rules", pol.get_security_rules(), max_rows=30)
    out += _section("NAT Rules", pol.get_nat_rules(), max_rows=25)
    out += _section("PBF Rules", pol.get_pbf_rules())
    out += _section("Decryption Rules", pol.get_decryption_rules())
    out += _section("QoS Rules", pol.get_qos_rules())
    out += _section("DoS Protection Rules", pol.get_dos_rules())

    # Objects
    out += _section("Address Objects", obj.get_addresses(), max_rows=30)
    out += _section("Address Groups", obj.get_address_groups())
    out += _section("Services", obj.get_services(), max_rows=25)
    out += _section("Service Groups", obj.get_service_groups())
    out += _section("Tags", obj.get_tags())
    out += _section("Security Profile Groups", obj.get_security_profile_groups())
    out += _section("Custom URL Categories", obj.get_custom_url_categories())
    out += _section("Log Forwarding Profiles", obj.get_log_forwarding_profiles())

    # Network
    out += _section("Ethernet Interfaces", net.get_ethernet_interfaces(), max_rows=30)
    out += _section("VLAN Interfaces", net.get_vlan_interfaces())
    out += _section("Loopback Interfaces", net.get_loopback_interfaces())
    out += _section("Tunnel Interfaces", net.get_tunnel_interfaces())
    out += _section("Zones", net.get_zones(), max_rows=25)
    out += _section("Virtual Routers", net.get_virtual_routers())
    out += _section("IPsec Tunnels (VPN)", net.get_ipsec_tunnels())
    out += _section("IKE Gateways", net.get_ike_gateways())
    out += _section("DHCP Servers", net.get_dhcp_servers())
    out += _section("GlobalProtect Portals", net.get_gp_portals())
    out += _section("GlobalProtect Gateways", net.get_gp_gateways())

    # Device
    out += _section("Administrators", dev.get_admins())
    out += _section("Authentication Profiles", dev.get_auth_profiles())
    out += _section("Certificates", dev.get_certificates())

    return "\n".join(out)


def _extract_fortigate_summary(text: str) -> str:
    """Legacy regex-based fallback. Only used if the real parser
    (_build_fortigate_summary_from_parser) raises — e.g. on a malformed
    or unexpectedly-structured file. Kept so a parser bug degrades to a
    coarser summary rather than no chat functionality at all.
    """
    lines = text.splitlines()
    sections: dict[str, list[str]] = {}
    current_section = None
    current_block: list[str] = []
    depth = 0

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("config "):
            if depth == 0:
                current_section = stripped[len("config ") :].strip()
                sections.setdefault(current_section, [])
            depth += 1
        elif stripped == "end":
            depth = max(0, depth - 1)
            if depth == 0:
                current_section = None
        elif current_section and depth == 1 and stripped.startswith("edit "):
            current_block = [stripped]
        elif current_section and depth == 1 and stripped == "next":
            if current_block:
                sections[current_section].append(" | ".join(current_block))
            current_block = []
        elif current_section and current_block and stripped.startswith("set "):
            current_block.append(stripped)

    out = ["=== FortiGate Config Summary (fallback regex extraction) ==="]
    for section, entries in sections.items():
        out.append(f"\n[{section}] — {len(entries)} entries")
        sample_count = min(len(entries), 25)
        for entry in entries[:sample_count]:
            out.append(f"  - {entry}")
        if len(entries) > sample_count:
            out.append(
                f"  ... and {len(entries) - sample_count} more entries omitted for brevity"
            )

    return "\n".join(out)


def _extract_paloalto_summary(text: str) -> str:
    """Legacy regex-based fallback. Only used if the real parser
    (_build_paloalto_summary_from_parser) raises — e.g. on malformed XML.
    """
    entry_names = re.findall(r'<entry\s+name="([^"]+)"', text)
    rulebase_rules = re.findall(r"<rules>.*?</rules>", text, flags=re.DOTALL)

    out = ["=== Palo Alto Config Summary (fallback regex extraction) ==="]
    out.append(f"\nTotal named <entry> elements found: {len(entry_names)}")

    sample_count = min(len(entry_names), 50)
    if entry_names:
        out.append(f"Sample entry names (first {sample_count}):")
        for name in entry_names[:sample_count]:
            out.append(f"  - {name}")
        if len(entry_names) > sample_count:
            out.append(
                f"  ... and {len(entry_names) - sample_count} more omitted for brevity"
            )

    out.append(f"\nDetected {len(rulebase_rules)} <rules> block(s) in the config.")
    return "\n".join(out)


def build_config_summary(raw_text: str, vendor: str) -> str:
    """Build a bounded-size text summary of the config for LLM context,
    using the real parser classes (FortiGateParser / Palo Alto parsers)
    so the chatbot has access to every config area those parsers
    understand. Falls back to coarser regex extraction only if the real
    parser raises on this specific file.
    """
    try:
        if vendor == "Palo Alto":
            import xml.etree.ElementTree as ET

            root = ET.fromstring(raw_text)
            summary = _build_paloalto_summary_from_parser(root)
        else:
            summary = _build_fortigate_summary_from_parser(raw_text)
    except Exception as e:
        try:
            if vendor == "Palo Alto":
                summary = _extract_paloalto_summary(raw_text)
            else:
                summary = _extract_fortigate_summary(raw_text)
            summary += f"\n\n[Note: used fallback extraction due to: {e}]"
        except Exception:
            summary = ""

    if not summary.strip():
        summary = "=== Raw config (truncated) ===\n" + raw_text[:MAX_SUMMARY_CHARS]

    if len(summary) > MAX_SUMMARY_CHARS:
        summary = (
            summary[:MAX_SUMMARY_CHARS]
            + "\n... [summary truncated to fit context budget]"
        )

    return summary


# ──────────────────────────────────────────────────────────────────────────
# 3. Google Gemini API call
# ──────────────────────────────────────────────────────────────────────────


def _get_client():
    """Safely read the API key, even when no secrets.toml file exists at all.

    Accessing st.secrets when no secrets file is present anywhere raises
    StreamlitSecretNotFoundError rather than behaving like an empty dict,
    so we must catch that explicitly (hasattr check alone isn't enough —
    the attribute always exists, it just raises on access).
    """
    try:
        api_key = st.secrets.get("GEMINI_API_KEY", None)
    except Exception:
        api_key = None

    if not api_key:
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

    if not api_key:
        return None
    return genai.Client(api_key=api_key)


def ask_gemini(
    question: str,
    config_summary: str,
    vendor: str,
    filename: str,
    chat_history: list[dict],
    vendor_mismatch: str | None = None,
) -> str:
    """Send the question + config summary + recent history to Gemini, return the reply text.

    `vendor_mismatch`, when set, is the vendor the file's CONTENT actually
    looks like (per detect_vendor_from_content), when it disagrees with
    `vendor` (which came from the file extension). We tell Gemini about
    this explicitly so it can flag the discrepancy to the user instead of
    confidently parsing FortiGate CLI syntax as if it were Palo Alto XML
    (or vice versa) just because the filename said so.
    """
    if genai is None:
        return "⚠️ The `google-genai` package isn't installed. Run `pip install google-genai`."

    client = _get_client()
    if client is None:
        return (
            "⚠️ No Gemini API key found. Add `GEMINI_API_KEY` to "
            "`.streamlit/secrets.toml` to enable the chatbot. Get a free key at "
            "https://aistudio.google.com/app/apikey"
        )

    mismatch_note = ""
    if vendor_mismatch and vendor_mismatch != vendor:
        mismatch_note = f"""
⚠️ NOTE: the file extension/upload flow indicated this is a {vendor} config,
but the actual file CONTENT looks structurally like a {vendor_mismatch} config
(based on syntax patterns, not the filename). If the user asks something that
doesn't fit a {vendor} file, mention this discrepancy rather than forcing an
answer that assumes the wrong format — the file may have been mislabeled or
uploaded with the wrong extension.
"""

    system_prompt = f"""You are a firewall configuration assistant embedded in a config analysis tool.

The user has uploaded a {vendor} firewall configuration file named "{filename}".
{"Palo Alto PAN-OS configs are XML-based (nested <entry name=\"...\"> elements)." if vendor == "Palo Alto" else "FortiGate FortiOS configs use line-based CLI syntax (config/edit/set/next/end blocks)."}
{mismatch_note}
Below is a structured summary extracted from that configuration (the full file may be
multiple megabytes, so this is a condensed extraction of the most relevant elements,
not the complete raw file).

Answer the user's questions ONLY using this configuration data. If the summary doesn't
contain enough detail to fully answer (e.g. they ask about a specific rule that wasn't
included in the sampled summary), say so clearly and suggest they check that section
directly in the tool rather than guessing.

Be concise and technical — the user is a network/security engineer.

=== CONFIG SUMMARY ===
{config_summary}
=== END CONFIG SUMMARY ==="""

    trimmed_history = chat_history[-10:]

    # Gemini's `contents` format: roles are "user"/"model" (not "assistant"),
    # each turn's text goes under a "parts" list, and the system prompt is
    # passed via config.system_instruction rather than inside contents.
    contents = []
    for m in trimmed_history:
        gemini_role = "model" if m["role"] == "assistant" else "user"
        contents.append({"role": gemini_role, "parts": [{"text": m["content"]}]})
    contents.append({"role": "user", "parts": [{"text": question}]})

    try:
        response = client.models.generate_content(
            model=MODEL,
            contents=contents,
            config=genai_types.GenerateContentConfig(
                system_instruction=system_prompt,
                max_output_tokens=1024,
            ),
        )
        return response.text
    except Exception as e:
        return f"⚠️ Error contacting Gemini: {e}"


# ──────────────────────────────────────────────────────────────────────────
# 4. Theme-aware palette
# ──────────────────────────────────────────────────────────────────────────


def _palette():
    """Colors for the chat panel, following the app's own theme toggle
    (st.session_state.theme). Accent uses a teal/violet pairing distinct
    from the app's primary blue, so the chatbot reads as a deliberate,
    distinct feature rather than a generic clone of the rest of the UI.
    """
    theme = st.session_state.get("theme", "dark")
    if theme == "dark":
        return {
            "panel_bg_1": "#161b22",
            "panel_bg_2": "#11151b",
            "border": "#2d3440",
            "text": "#e6edf3",
            "text_dim": "#8b949e",
            "header_bg_1": "#1c2330",
            "header_bg_2": "#161b22",
            "user_bubble_bg": "linear-gradient(135deg, #6e56cf33, #6e56cf14)",
            "user_bubble_border": "#6e56cf55",
            "assistant_bubble_bg": "#1c2330",
            "assistant_bubble_border": "#2d3440",
            "assistant_text": "#d6dce5",
            "accent_grad": "linear-gradient(145deg, #14b8a6, #6e56cf)",
            "accent_shadow": "rgba(20,184,166,0.45)",
            "accent_shadow_hover": "rgba(110,86,207,0.55)",
            "input_bg": "#0d1117",
            "scrollbar_thumb": "#2d3440",
        }
    else:
        return {
            "panel_bg_1": "#ffffff",
            "panel_bg_2": "#f6f8fa",
            "border": "#d8dee4",
            "text": "#1f2328",
            "text_dim": "#57606a",
            "header_bg_1": "#eef0ff",
            "header_bg_2": "#ffffff",
            "user_bubble_bg": "linear-gradient(135deg, #6e56cf22, #6e56cf0c)",
            "user_bubble_border": "#6e56cf44",
            "assistant_bubble_bg": "#f6f8fa",
            "assistant_bubble_border": "#d8dee4",
            "assistant_text": "#1f2328",
            "accent_grad": "linear-gradient(145deg, #0d9488, #6e56cf)",
            "accent_shadow": "rgba(13,148,136,0.35)",
            "accent_shadow_hover": "rgba(110,86,207,0.45)",
            "input_bg": "#ffffff",
            "scrollbar_thumb": "#d8dee4",
        }


# ──────────────────────────────────────────────────────────────────────────
# 5. Floating chat UI
# ──────────────────────────────────────────────────────────────────────────


def _inject_chat_css(size: str):
    preset = SIZE_PRESETS[size]
    is_overlay = size == "overlay"
    pal = _palette()

    st.markdown(
        f"""
        <style>
        /* Toggle button — st.container(key="fw_toggle_box") renders with
           CSS class "st-key-fw_toggle_box", a stable, exact target. */
        div.st-key-fw_toggle_box {{
            position: fixed !important;
            bottom: 24px;
            right: 24px;
            z-index: 9999;
            width: 60px !important;
        }}
        div.st-key-fw_toggle_box button {{
            border-radius: 50% !important;
            width: 60px !important;
            height: 60px !important;
            font-size: 24px !important;
            border: none !important;
            background: {pal['accent_grad']} !important;
            box-shadow: 0 6px 20px {pal['accent_shadow']}, 0 2px 6px rgba(0,0,0,0.25) !important;
            padding: 0 !important;
            transition: transform 0.15s ease, box-shadow 0.15s ease !important;
        }}
        div.st-key-fw_toggle_box button:hover {{
            transform: scale(1.06) !important;
            box-shadow: 0 8px 26px {pal['accent_shadow_hover']}, 0 2px 8px rgba(0,0,0,0.3) !important;
        }}

        /* Panel container */
        div.st-key-fw_panel_box {{
            position: fixed !important;
            {"top: 50%; left: 50%; transform: translate(-50%, -50%);" if is_overlay else "bottom: 96px; right: 24px;"}
            width: {preset['width']} !important;
            height: {preset['height']} !important;
            max-width: 94vw;
            max-height: 82vh;
            background: linear-gradient(165deg, {pal['panel_bg_1']} 0%, {pal['panel_bg_2']} 100%);
            border: 1px solid {pal['border']};
            border-radius: 18px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.35), 0 0 0 1px {pal['accent_shadow']};
            z-index: 9998;
            padding: 0;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            animation: fw-panel-in 0.18s ease-out;
        }}

        @keyframes fw-panel-in {{
            from {{ opacity: 0; transform: {"translate(-50%, -50%) scale(0.97)" if is_overlay else "translateY(8px)"}; }}
            to   {{ opacity: 1; transform: {"translate(-50%, -50%) scale(1)" if is_overlay else "translateY(0)"}; }}
        }}

        {f'''
        div.st-key-fw_backdrop_box {{
            position: fixed !important;
            inset: 0 !important;
            background: rgba(5,8,12,0.55) !important;
            z-index: 9997 !important;
            backdrop-filter: blur(2px);
        }}
        ''' if is_overlay else ''}

        /* Header bar */
        .fw-chat-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 14px 16px;
            background: linear-gradient(90deg, {pal['header_bg_1']}, {pal['header_bg_2']});
            border-bottom: 1px solid {pal['border']};
            flex-shrink: 0;
        }}
        .fw-chat-header-title {{
            font-size: 14px;
            font-weight: 700;
            color: {pal['text']};
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .fw-chat-header-sub {{
            font-size: 11px;
            color: {pal['text_dim']};
            margin-top: 2px;
        }}

        /* Message list container — st.container(height=..., key="fw_chat_scroll")
           gives genuinely native scrolling (Streamlit handles the
           overflow/scrollbar mechanics internally), so we only need to
           style its background/padding here, not fight Streamlit's
           internal flex layout the way an earlier version of this file
           did. autoscroll=True on that container also means Streamlit
           scrolls it to the bottom automatically when a new message is
           added — no custom JS needed for that either. */
        div.st-key-fw_chat_scroll {{
            padding: 4px 16px 8px !important;
        }}
        div.st-key-fw_chat_scroll::-webkit-scrollbar {{
            width: 6px;
        }}
        div.st-key-fw_chat_scroll::-webkit-scrollbar-thumb {{
            background: {pal['scrollbar_thumb']};
            border-radius: 3px;
        }}

        .fw-chat-msg-user {{
            background: {pal['user_bubble_bg']};
            border: 1px solid {pal['user_bubble_border']};
            border-radius: 12px 12px 2px 12px;
            padding: 9px 13px;
            margin: 0 0 10px auto;
            margin-left: 15%;
            font-size: 13px;
            color: {pal['text']};
            white-space: pre-wrap;
            box-shadow: 0 2px 6px rgba(0,0,0,0.12);
        }}
        .fw-chat-msg-assistant {{
            background: {pal['assistant_bubble_bg']};
            border: 1px solid {pal['assistant_bubble_border']};
            border-radius: 12px 12px 12px 2px;
            padding: 9px 13px;
            margin: 0 15% 10px 0;
            font-size: 13px;
            color: {pal['assistant_text']};
            white-space: pre-wrap;
            box-shadow: 0 2px 6px rgba(0,0,0,0.08);
        }}
        .fw-chat-msg-label {{
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            opacity: 0.6;
            display: block;
            margin-bottom: 3px;
        }}

        @keyframes fw-thinking-pulse {{
            0%, 100% {{ opacity: 0.3; }}
            50% {{ opacity: 1; }}
        }}
        .fw-thinking-dot {{
            display: inline-block;
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: #14b8a6;
            animation: fw-thinking-pulse 1s infinite ease-in-out;
        }}

        /* Size-toggle icon buttons in header */
        div.st-key-fw_size_compact button, div.st-key-fw_size_expanded button,
        div.st-key-fw_size_overlay button, div.st-key-fw_close_btn button {{
            background: transparent !important;
            border: 1px solid {pal['border']} !important;
            color: {pal['text_dim']} !important;
            font-size: 12px !important;
            padding: 3px 9px !important;
            border-radius: 7px !important;
            min-height: 28px !important;
            box-shadow: none !important;
        }}
        div.st-key-fw_size_compact button:hover, div.st-key-fw_size_expanded button:hover,
        div.st-key-fw_size_overlay button:hover, div.st-key-fw_close_btn button:hover {{
            border-color: #14b8a6 !important;
            color: #14b8a6 !important;
            transform: none !important;
        }}

        /* The size-control row and chat input must stay fixed-height and
           never shrink — only .fw-chat-body (the message list) should
           flex/scroll. */
        div.st-key-fw_panel_box [data-testid="stHorizontalBlock"] {{
            flex-shrink: 0 !important;
        }}

        /* Chat input — Streamlit renders this input's background as
           white regardless of the app's theme (confirmed: an earlier
           attempt to force a dark background here didn't reliably reach
           the actual input surface). Rather than keep fighting that,
           the fix is simpler and more robust: always use dark text,
           since the background is reliably light either way. This
           guarantees readable contrast in both themes without depending
           on a CSS selector that may not match Streamlit's internal
           DOM consistently. */
        div.st-key-fw_panel_box [data-testid="stChatInput"] {{
            flex-shrink: 0 !important;
        }}
        div.st-key-fw_panel_box [data-testid="stChatInput"] textarea {{
            color: #1f2328 !important;
            caret-color: #1f2328 !important;
            /* Cap how tall the input can grow as the user types a long
               prompt, and scroll internally past that point instead of
               growing indefinitely — an unbounded textarea was what
               pushed the submit button out of the visible panel for
               long prompts, the same class of bug as the AI response
               area before the height fix. */
            max-height: 120px !important;
            overflow-y: auto !important;
        }}
        div.st-key-fw_panel_box [data-testid="stChatInput"] textarea::placeholder {{
            color: #6b7280 !important;
            opacity: 1 !important;
        }}

        @media (max-width: 480px) {{
            div.st-key-fw_panel_box {{
                width: 92vw !important;
                right: 4vw;
            }}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def _escape(text: str) -> str:
    """Minimal HTML escaping so user/AI text can't break wrapper divs
    or inject markup (XSS) when rendered with unsafe_allow_html=True."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_chatbox(vendor: str, filename: str, raw_text: str):
    """Render the floating chat button + panel. Call once per page render,
    only after a config has been successfully loaded.

    Three size modes (compact / expanded / overlay) all use the SAME
    session_state.chat_history — switching sizes never loses context,
    unlike a real new browser tab would (see module docstring).
    """
    if "chat_open" not in st.session_state:
        st.session_state.chat_open = False
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []
    if "config_summary" not in st.session_state:
        st.session_state.config_summary = None
    if "chat_size" not in st.session_state:
        st.session_state.chat_size = "compact"
    if "vendor_content_check" not in st.session_state:
        st.session_state.vendor_content_check = None
    if "fw_awaiting_answer" not in st.session_state:
        st.session_state.fw_awaiting_answer = False

    if st.session_state.config_summary is None:
        with st.spinner("Preparing config for chat..."):
            st.session_state.config_summary = build_config_summary(raw_text, vendor)
            st.session_state.vendor_content_check = detect_vendor_from_content(raw_text)

    size = st.session_state.chat_size
    pal = _palette()
    _inject_chat_css(size)

    # ── Toggle button (always visible) ───────────────────────
    with st.container(key="fw_toggle_box"):
        icon = "✕" if st.session_state.chat_open else "💬"
        if st.button(icon, key="fw_chat_toggle_btn"):
            st.session_state.chat_open = not st.session_state.chat_open
            st.rerun()

    if not st.session_state.chat_open:
        return

    if size == "overlay":
        with st.container(key="fw_backdrop_box"):
            pass

    with st.container(key="fw_panel_box"):
        st.markdown(
            f"""
            <div class="fw-chat-header">
                <div>
                    <div class="fw-chat-header-title">
                        💬 Config Assistant
                    </div>
                    <div class="fw-chat-header-sub">{_escape(filename)} · {vendor}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        ctrl_cols = st.columns([1, 1, 1, 1, 5])
        with ctrl_cols[0]:
            if st.button("▢", key="fw_size_compact", help="Compact"):
                st.session_state.chat_size = "compact"
                st.rerun()
        with ctrl_cols[1]:
            if st.button("⬚", key="fw_size_expanded", help="Expanded"):
                st.session_state.chat_size = "expanded"
                st.rerun()
        with ctrl_cols[2]:
            if st.button("⛶", key="fw_size_overlay", help="Large overlay view"):
                st.session_state.chat_size = "overlay"
                st.rerun()
        with ctrl_cols[3]:
            if st.button("✕", key="fw_close_btn", help="Close"):
                st.session_state.chat_open = False
                st.rerun()

        # Surface a vendor/content mismatch warning once, near the top of
        # the conversation, rather than only burying it in Gemini's prose.
        mismatch = st.session_state.vendor_content_check
        if mismatch and mismatch != vendor:
            st.warning(
                f"This file is being treated as **{vendor}** based on its name/extension, "
                f"but its content looks structurally like a **{mismatch}** config. "
                f"Answers below may be unreliable until this is resolved.",
                icon="⚠️",
            )

        # Message list: a native Streamlit scrolling container. Using
        # st.container(height=..., autoscroll=True) instead of a hand-built
        # HTML div with CSS overflow fixes two real problems:
        # 1. Auto-scroll: Streamlit scrolls this container to the bottom
        #    automatically whenever new content is added (e.g. a new AI
        #    reply), so the user never has to manually scroll down to see
        #    a long response — this was the main bug being reported.
        # 2. Rendering safety: each message is now rendered in its OWN
        #    st.markdown call rather than joined into one giant HTML
        #    string. AI-generated text can contain backticks, asterisks,
        #    or other markdown-significant characters that — when mixed
        #    into one big hand-built div soup — could cause Streamlit's
        #    markdown parser to misparse the structure and render content
        #    outside the intended wrapper (which is what produced the
        #    "response escapes the panel" bug in the screenshot).
        message_area_height = _MESSAGE_AREA_HEIGHTS[size]
        with st.container(
            height=message_area_height, key="fw_chat_scroll", border=False
        ):
            if not st.session_state.chat_history:
                # A real greeting bubble (not just hint text) — this both
                # answers the request for the assistant to open the
                # conversation politely, and gives the empty message area
                # actual content to fill instead of leaving a large blank
                # gap above the input box.
                greeting = (
                    f"Hello! I've loaded your {vendor} configuration "
                    f"(<code>{_escape(filename)}</code>). How may I help you "
                    f"analyze it today?"
                )
                st.markdown(
                    f'<div class="fw-chat-msg-assistant"><span class="fw-chat-msg-label">Assistant</span>{greeting}</div>',
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f'<div style="color:{pal["text_dim"]};font-size:11px;padding:6px 4px 2px;">'
                    "You could try asking:<br>"
                    '• "What policies allow traffic to the internet?"<br>'
                    '• "List all interfaces in zone DMZ."<br>'
                    '• "Are there any deny-all rules?"'
                    "</div>",
                    unsafe_allow_html=True,
                )
            for msg in st.session_state.chat_history:
                if msg["role"] == "user":
                    st.markdown(
                        f'<div class="fw-chat-msg-user"><span class="fw-chat-msg-label">You</span>{_escape(msg["content"])}</div>',
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f'<div class="fw-chat-msg-assistant"><span class="fw-chat-msg-label">Abang AI</span>{_escape(msg["content"])}</div>',
                        unsafe_allow_html=True,
                    )

            # Thinking indicator: rendered INSIDE the scrollable message
            # area, as the last item, while a question is being answered.
            # Placing it here (rather than wrapping the API call in
            # st.spinner after st.chat_input is called below) is what
            # makes it appear directly above the input box instead of
            # below the whole panel — Streamlit renders elements in the
            # order they're called, so a spinner called after chat_input
            # would render below it, which is the bug being pointed at in
            # the screenshot's red annotation.
            thinking_placeholder = st.empty()
            if st.session_state.get("fw_awaiting_answer"):
                thinking_placeholder.markdown(
                    f'<div style="color:{pal["text_dim"]};font-size:12px;'
                    f'padding:4px 2px;display:flex;align-items:center;gap:6px;">'
                    f'<span class="fw-thinking-dot"></span> Thinking…</div>',
                    unsafe_allow_html=True,
                )

        question = st.chat_input(
            "Ask a question about this config...", key="fw_chat_input"
        )
        if question:
            st.session_state.chat_history.append({"role": "user", "content": question})
            st.session_state.fw_awaiting_answer = True
            st.rerun()

        # The actual API call happens on the rerun AFTER the user's message
        # is already appended and displayed — this two-phase approach
        # (append + rerun, then answer + rerun) is what lets the "Thinking…"
        # indicator above actually render and be visible to the user before
        # the (potentially slow) Gemini call blocks the script. Calling
        # ask_gemini() synchronously in the same run as appending the
        # question would mean the indicator and the API call happen in the
        # same frame, so the user would never actually see "Thinking…" —
        # it would appear and resolve before the page ever repaints.
        #
        # NOTE: this deliberately does NOT use st.spinner() here. Streamlit
        # renders elements in call order, and this code runs AFTER
        # st.chat_input() above — so a spinner called here would render
        # below the input box, not above it. The "Thinking…" indicator the
        # user actually sees is thinking_placeholder, rendered earlier
        # inside the message container, before chat_input is called.
        if st.session_state.get("fw_awaiting_answer"):
            answer = ask_gemini(
                question=st.session_state.chat_history[-1]["content"],
                config_summary=st.session_state.config_summary,
                vendor=vendor,
                filename=filename,
                chat_history=st.session_state.chat_history[:-1],
                vendor_mismatch=st.session_state.vendor_content_check,
            )
            st.session_state.chat_history.append(
                {"role": "assistant", "content": answer}
            )
            st.session_state.fw_awaiting_answer = False
            st.rerun()
