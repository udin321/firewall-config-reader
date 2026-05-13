"""
app.py  –  Firewall Config Reader
Enterprise-grade, cybersecurity-themed, dark-mode UI
"""

import os
import time
import base64
import hashlib
from pathlib import Path

import streamlit as st

# ── Page config must be FIRST ────────────────────────────────────────────────
st.set_page_config(
    page_title="Firewall Config Reader",
    page_icon="🔥",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Security: basic session auth ─────────────────────────────────────────────
_VALID_TOKENS = {}


def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def require_auth():
    """Simple password gate — set FW_PASSWORD env var to enable."""
    pw_required = os.environ.get("FW_PASSWORD", "")
    if not pw_required:
        return True  # No password set → open access (localhost dev)

    if st.session_state.get("authenticated"):
        return True

    st.markdown(
        """
    <div style="max-width:380px;margin:80px auto;background:#161b22;
                border:1px solid #30363d;border-radius:14px;padding:36px">
        <div style="text-align:center;margin-bottom:24px">
            <span style="font-size:40px">🔒</span>
            <h2 style="color:#e6edf3;margin:8px 0 4px">Firewall Config Reader</h2>
            <p style="color:#8b949e;font-size:13px">Authentication required</p>
        </div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    pw = st.text_input(
        "Password", type="password", key="auth_pw", placeholder="Enter access password"
    )
    if st.button("Sign In", use_container_width=True):
        if _hash(pw) == _hash(pw_required):
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("❌ Incorrect password.")
            time.sleep(1)  # Brute-force delay
    return False


# ── CSS injection ─────────────────────────────────────────────────────────────
def inject_css():
    theme = st.session_state.get("theme", "dark")
    if theme == "dark":
        bg = "#0d1117"
        bg2 = "#161b22"
        bg3 = "#21262d"
        border = "#30363d"
        text = "#e6edf3"
        text2 = "#8b949e"
        accent = "#3a7bd5"
        accent2 = "#58a6ff"
        success = "#3fb950"
        warning = "#d29922"
        danger = "#f85149"
        card_bg = "#161b22"
    else:
        bg = "#f6f8fa"
        bg2 = "#ffffff"
        bg3 = "#eaeef2"
        border = "#d0d7de"
        text = "#1f2328"
        text2 = "#656d76"
        accent = "#0969da"
        accent2 = "#0550ae"
        success = "#1a7f37"
        warning = "#9a6700"
        danger = "#cf222e"
        card_bg = "#ffffff"

    st.markdown(
        f"""
    <style>
    /* ── Root reset ──────────────────────────────────── */
    html, body, [class*="css"] {{
        font-family: 'Inter', 'Segoe UI', system-ui, sans-serif !important;
    }}
    .stApp {{
        background: {bg} !important;
        color: {text} !important;
    }}

    /* ── Hide default streamlit chrome ─────────────── */
    #MainMenu, footer, header {{ visibility: hidden; }}
    .block-container {{ padding-top: 1rem !important; max-width: 100% !important; }}

    /* ── Custom topbar ──────────────────────────────── */
    .fw-topbar {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        background: {bg2};
        border-bottom: 1px solid {border};
        padding: 12px 24px;
        position: sticky;
        top: 0;
        z-index: 1000;
        margin: -1rem -1rem 1.5rem -1rem;
    }}
    .fw-topbar-brand {{
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 17px;
        font-weight: 700;
        color: {text};
        letter-spacing: -0.3px;
    }}
    .fw-topbar-brand span {{ color: {accent2}; }}
    .fw-topbar-right {{
        display: flex;
        align-items: center;
        gap: 16px;
    }}

    /* ── Theme toggle pill ──────────────────────────── */
    .theme-toggle-wrapper {{
        display: flex;
        align-items: center;
        gap: 8px;
        font-size: 13px;
        color: {text2};
    }}
    .toggle-pill {{
        position: relative;
        width: 42px;
        height: 22px;
        background: {"#3a7bd5" if theme == "dark" else border};
        border-radius: 11px;
        cursor: pointer;
        transition: background 0.25s;
        display: inline-block;
        vertical-align: middle;
        border: none;
    }}
    .toggle-pill::after {{
        content: "";
        position: absolute;
        top: 2px;
        left: {"20px" if theme == "dark" else "2px"};
        width: 18px;
        height: 18px;
        background: white;
        border-radius: 50%;
        transition: left 0.25s;
        box-shadow: 0 1px 3px rgba(0,0,0,0.3);
    }}

    /* ── Sidebar ────────────────────────────────────── */
    [data-testid="stSidebar"] {{
        background: {bg2} !important;
        border-right: 1px solid {border} !important;
        min-width: 220px !important;
    }}
    [data-testid="stSidebar"] .block-container {{
        padding: 1.5rem 1rem !important;
    }}
    .sidebar-logo {{
        text-align: center;
        padding: 0 0 20px 0;
        border-bottom: 1px solid {border};
        margin-bottom: 20px;
    }}
    .sidebar-logo h2 {{
        font-size: 16px;
        font-weight: 700;
        color: {accent2};
        margin: 10px 0 4px;
        letter-spacing: -0.3px;
    }}
    .sidebar-logo p {{
        font-size: 11px;
        color: {text2};
        margin: 0;
    }}
    .nav-item {{
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 9px 12px;
        border-radius: 8px;
        font-size: 13.5px;
        color: {text2};
        cursor: pointer;
        transition: all 0.15s;
        margin-bottom: 2px;
        border: 1px solid transparent;
    }}
    .nav-item:hover {{
        background: {bg3};
        color: {text};
        border-color: {border};
    }}
    .nav-item.active {{
        background: {accent}22;
        color: {accent2};
        border-color: {accent}44;
        font-weight: 600;
    }}

    /* ── Cards ──────────────────────────────────────── */
    .fw-card {{
        background: {card_bg};
        border: 1px solid {border};
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 16px;
        transition: border-color 0.2s, box-shadow 0.2s;
    }}
    .fw-card:hover {{
        border-color: {accent}66;
        box-shadow: 0 0 0 3px {accent}11;
    }}
    .fw-card-title {{
        font-size: 13px;
        font-weight: 600;
        color: {text2};
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 8px;
    }}
    .fw-card-value {{
        font-size: 28px;
        font-weight: 700;
        color: {text};
        line-height: 1;
    }}
    .fw-card-sub {{
        font-size: 12px;
        color: {text2};
        margin-top: 6px;
    }}

    /* ── Metric badge ───────────────────────────────── */
    .fw-badge {{
        display: inline-flex;
        align-items: center;
        gap: 5px;
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 600;
        border: 1px solid;
    }}
    .fw-badge-allow  {{ color:{success};  background:{success}18;  border-color:{success}44; }}
    .fw-badge-deny   {{ color:{danger};   background:{danger}18;   border-color:{danger}44;  }}
    .fw-badge-info   {{ color:{accent2};  background:{accent}18;   border-color:{accent}44;  }}
    .fw-badge-warn   {{ color:{warning};  background:{warning}18;  border-color:{warning}44; }}

    /* ── Section headers ────────────────────────────── */
    .fw-section-header {{
        display: flex;
        align-items: center;
        gap: 10px;
        font-size: 15px;
        font-weight: 700;
        color: {text};
        padding: 10px 0 10px;
        border-bottom: 1px solid {border};
        margin-bottom: 16px;
        letter-spacing: -0.2px;
    }}
    .fw-section-header .dot {{
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: {accent};
    }}

    /* ── Upload area ────────────────────────────────── */
    [data-testid="stFileUploader"] {{
        background: {bg2} !important;
        border: 2px dashed {border} !important;
        border-radius: 14px !important;
        padding: 24px !important;
        transition: border-color 0.2s !important;
    }}
    [data-testid="stFileUploader"]:hover {{
        border-color: {accent} !important;
        background: {accent}08 !important;
    }}
    [data-testid="stFileUploader"] label {{
        color: {text2} !important;
        font-size: 14px !important;
    }}

    /* ── Tables ─────────────────────────────────────── */
    [data-testid="stDataFrame"] {{
        border: 1px solid {border} !important;
        border-radius: 10px !important;
        overflow: hidden;
    }}
    .dataframe thead tr th {{
        background: {bg3} !important;
        color: {text2} !important;
        font-size: 12px !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.4px !important;
        border-bottom: 1px solid {border} !important;
        padding: 8px 12px !important;
    }}
    .dataframe tbody tr td {{
        font-size: 13px !important;
        padding: 7px 12px !important;
        border-bottom: 1px solid {border}66 !important;
        color: {text} !important;
    }}
    .dataframe tbody tr:hover td {{
        background: {accent}0a !important;
    }}
    .dataframe tbody tr:last-child td {{
        border-bottom: none !important;
    }}

    /* ── Tabs ───────────────────────────────────────── */
    [data-testid="stTabs"] [role="tablist"] {{
        gap: 4px;
        border-bottom: 1px solid {border};
        overflow-x: auto !important;
        overflow-y: visible !important;
        flex-wrap: nowrap !important;
        -webkit-overflow-scrolling: touch;
        scrollbar-width: thin;
        padding-bottom: 2px;
    }}
    [data-testid="stTabs"] [role="tablist"]::-webkit-scrollbar {{
        height: 3px;
    }}
    [data-testid="stTabs"] [role="tablist"]::-webkit-scrollbar-thumb {{
        background: {border};
        border-radius: 2px;
    }}
    [data-testid="stTabs"] [role="tab"] {{
        background: transparent !important;
        border: 1px solid transparent !important;
        border-radius: 8px 8px 0 0 !important;
        color: {text2} !important;
        font-size: 13px !important;
        padding: 7px 14px !important;
        transition: all 0.15s !important;
        white-space: nowrap !important;
        flex-shrink: 0 !important;
    }}
    [data-testid="stTabs"] [role="tab"][aria-selected="true"] {{
        background: {bg3} !important;
        border-color: {border} {border} {bg3} !important;
        color: {accent2} !important;
        font-weight: 600 !important;
    }}
    [data-testid="stTabs"] [role="tab"]:hover {{
        color: {text} !important;
        background: {bg3}88 !important;
    }}

    /* ── Expanders ──────────────────────────────────── */
    [data-testid="stExpander"] {{
        background: {bg2} !important;
        border: 1px solid {border} !important;
        border-radius: 10px !important;
        margin-bottom: 8px !important;
    }}
    [data-testid="stExpander"] summary {{
        padding: 10px 16px !important;
        color: {text} !important;
        font-size: 14px !important;
        font-weight: 500 !important;
    }}
    [data-testid="stExpander"] summary:hover {{
        color: {accent2} !important;
    }}

    /* ── Buttons ────────────────────────────────────── */
    .stButton button {{
        background: {accent} !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        font-size: 13px !important;
        font-weight: 600 !important;
        padding: 8px 18px !important;
        transition: all 0.15s !important;
        letter-spacing: 0.2px !important;
        white-space: nowrap !important;
        min-width: fit-content !important;
        width: auto !important;
        overflow: visible !important;
    }}
    .stButton button:hover {{
        background: {accent2} !important;
        transform: translateY(-1px);
        box-shadow: 0 4px 12px {accent}44 !important;
    }}

    /* ── Selectbox / Input ──────────────────────────── */
    [data-testid="stSelectbox"], [data-testid="stTextInput"] {{
        border-radius: 8px !important;
    }}
    .stSelectbox > div > div,
    .stTextInput > div > div > input {{
        background: {bg3} !important;
        border-color: {border} !important;
        color: {text} !important;
        border-radius: 8px !important;
        font-size: 13px !important;
    }}

    /* ── Info / warning boxes ───────────────────────── */
    [data-testid="stAlert"] {{
        border-radius: 10px !important;
        border-left-width: 4px !important;
        font-size: 13px !important;
    }}

    /* ── Caption / small text ───────────────────────── */
    [data-testid="stCaptionContainer"] {{
        color: {text2} !important;
        font-size: 12px !important;
    }}

    /* ── Progress bar ───────────────────────────────── */
    [data-testid="stProgress"] > div > div {{
        background: linear-gradient(90deg, {accent}, {accent2}) !important;
        border-radius: 4px !important;
    }}

    /* ── Vendor card landing ─────────────────────────── */
    .vendor-card {{
        background: {bg2};
        border: 1px solid {border};
        border-radius: 16px;
        padding: 32px 24px;
        text-align: center;
        cursor: pointer;
        transition: all 0.2s;
        min-height: 200px;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 12px;
    }}
    .vendor-card:hover {{
        border-color: {accent};
        box-shadow: 0 0 0 3px {accent}22, 0 8px 24px rgba(0,0,0,0.3);
        transform: translateY(-2px);
    }}
    .vendor-card h3 {{
        font-size: 17px;
        font-weight: 700;
        color: {text};
        margin: 0;
    }}
    .vendor-card p {{
        font-size: 12px;
        color: {text2};
        margin: 0;
    }}

    /* ── Upload drop zone extra styling ─────────────── */
    .upload-zone {{
        background: {bg2};
        border: 2px dashed {border};
        border-radius: 16px;
        padding: 40px 32px;
        text-align: center;
        transition: all 0.2s;
        margin: 20px 0;
    }}
    .upload-zone:hover {{
        border-color: {accent};
        background: {accent}08;
    }}
    .upload-icon {{
        font-size: 40px;
        margin-bottom: 12px;
    }}
    .upload-title {{
        font-size: 16px;
        font-weight: 600;
        color: {text};
        margin-bottom: 6px;
    }}
    .upload-sub {{
        font-size: 13px;
        color: {text2};
    }}

    /* ── Status indicator dots ───────────────────────── */
    @keyframes pulse {{
        0% {{ opacity: 1; }}
        50% {{ opacity: 0.4; }}
        100% {{ opacity: 1; }}
    }}
    .status-dot-live {{
        display: inline-block;
        width: 8px; height: 8px;
        border-radius: 50%;
        background: {success};
        animation: pulse 2s infinite;
        margin-right: 6px;
    }}

    /* ── Horizontal rule ────────────────────────────── */
    hr {{ border-color: {border} !important; }}

    /* ── Metric override ────────────────────────────── */
    [data-testid="stMetric"] {{
        background: {bg2} !important;
        border: 1px solid {border} !important;
        border-radius: 10px !important;
        padding: 14px 18px !important;
    }}
    [data-testid="stMetricLabel"] {{
        color: {text2} !important;
        font-size: 12px !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.4px !important;
    }}
    [data-testid="stMetricValue"] {{
        color: {text} !important;
        font-size: 24px !important;
        font-weight: 700 !important;
    }}

    /* ── Scrollbar ──────────────────────────────────── */
    ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
    ::-webkit-scrollbar-track {{ background: {bg}; }}
    ::-webkit-scrollbar-thumb {{ background: {border}; border-radius: 3px; }}
    ::-webkit-scrollbar-thumb:hover {{ background: {text2}; }}
    </style>
    """,
        unsafe_allow_html=True,
    )


# ── Topbar with theme toggle ──────────────────────────────────────────────────
def render_topbar():
    theme = st.session_state.get("theme", "dark")
    icon = "☀️" if theme == "dark" else "🌙"
    label = "Light" if theme == "dark" else "Dark"

    # Fixed-width columns so buttons never wrap/reshape at narrow viewports
    col1, col2 = st.columns([8, 2])
    with col1:
        st.markdown(
            """
        <div class="fw-topbar-brand">
            🔥 <span>Firewall</span> Config Reader
            <span style="font-size:11px;background:#3a7bd522;color:#58a6ff;
                         padding:2px 8px;border-radius:10px;margin-left:8px;
                         border:1px solid #3a7bd544;font-weight:500">
                Enterprise
            </span>
        </div>
        """,
            unsafe_allow_html=True,
        )
    with col2:
        if st.button(
            f"{icon} {label}", key="theme_toggle", help="Toggle Dark / Light mode"
        ):
            st.session_state.theme = "light" if theme == "dark" else "dark"
            st.rerun()


# ── Sidebar navigation ────────────────────────────────────────────────────────
def render_sidebar(vendor: str | None):
    with st.sidebar:
        # Logo area
        st.markdown(
            """
        <div class="sidebar-logo">
            <div style="font-size:36px">🔥</div>
            <h2>FW Config Reader</h2>
            <p>Enterprise Security Analysis</p>
        </div>
        """,
            unsafe_allow_html=True,
        )

        if vendor:
            st.markdown(
                f"""
            <div style="background:#3a7bd522;border:1px solid #3a7bd544;
                        border-radius:8px;padding:8px 12px;margin-bottom:16px;
                        font-size:12px;color:#58a6ff;display:flex;
                        align-items:center;gap:6px">
                <span class="status-dot-live"></span>
                {vendor} config loaded
            </div>
            """,
                unsafe_allow_html=True,
            )

        st.markdown("**Navigation**")
        # These just display — actual navigation uses Streamlit tabs in main content
        nav_items = []
        if vendor == "Palo Alto":
            nav_items = [
                ("🏠", "Dashboard"),
                ("📋", "Policies"),
                ("📦", "Objects"),
                ("🌐", "Network"),
                ("⚙️", "Device"),
            ]
        elif vendor == "FortiGate":
            nav_items = [
                ("🏠", "Summary"),
                ("🔌", "Interfaces"),
                ("🌐", "Network"),
                ("📋", "Policy & Objects"),
                ("🔍", "Policy Lookup"),
                ("🔒", "Security"),
                ("🔑", "VPN"),
                ("👤", "User & Auth"),
                ("📡", "WiFi & Switch"),
                ("💻", "System"),
                ("📊", "Log & Report"),
            ]
        for icon, name in nav_items:
            st.markdown(
                f"""
            <div class="nav-item">
                <span>{icon}</span>
                <span>{name}</span>
            </div>
            """,
                unsafe_allow_html=True,
            )

        st.markdown("---")
        st.markdown(
            f"""
        <div style="font-size:11px;color:#8b949e;padding:4px 0;line-height:1.8">
            <div>📅 Session: {time.strftime('%Y-%m-%d %H:%M')}</div>
            <div>🔐 OWASP hardened</div>
            <div>⚡ v2.0.0</div>
        </div>
        """,
            unsafe_allow_html=True,
        )


# ── Landing / Upload page ─────────────────────────────────────────────────────
def render_landing():
    assets = Path(__file__).parent / "assets"

    st.markdown(
        """
    <div style="text-align:center;padding:40px 0 32px">
        <div style="font-size:52px;margin-bottom:16px">🔥</div>
        <h1 style="font-size:32px;font-weight:800;letter-spacing:-1px;margin:0 0 10px">
            Firewall Config Reader
        </h1>
        <p style="font-size:16px;color:#8b949e;max-width:480px;margin:0 auto">
            Upload your firewall configuration backup to begin analysis.
            Supports Palo Alto PAN-OS and FortiGate FortiOS.
        </p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # Vendor cards with logos
    c1, spacer, c2 = st.columns([5, 1, 5])

    def _img_b64(path: Path) -> str | None:
        if path.exists():
            return base64.b64encode(path.read_bytes()).decode()
        return None

    with c1:
        pa_b64 = _img_b64(assets / "paloalto_logo.png")
        if pa_b64:
            img_html = f'<img src="data:image/png;base64,{pa_b64}" style="max-height:64px;max-width:180px;object-fit:contain">'
        else:
            img_html = '<div style="font-size:14px;color:#58a6ff;background:#3a7bd522;padding:10px 20px;border-radius:8px;border:1px dashed #3a7bd5">📁 Add paloalto_logo.png<br>to assets/ folder</div>'

        st.markdown(
            f"""
        <div class="vendor-card">
            {img_html}
            <h3>Palo Alto Networks</h3>
            <p>PAN-OS .xml backup files</p>
            <div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:center;margin-top:4px">
                <span class="fw-badge fw-badge-info">PAN-OS 10.x+</span>
                <span class="fw-badge fw-badge-info">.xml</span>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with c2:
        fg_b64 = _img_b64(assets / "fortigate_logo.png")
        if fg_b64:
            img_html = f'<img src="data:image/png;base64,{fg_b64}" style="max-height:64px;max-width:180px;object-fit:contain">'
        else:
            img_html = '<div style="font-size:14px;color:#e87722;background:#e8772218;padding:10px 20px;border-radius:8px;border:1px dashed #e87722">📁 Add fortigate_logo.png<br>to assets/ folder</div>'

        st.markdown(
            f"""
        <div class="vendor-card">
            {img_html}
            <h3>FortiGate</h3>
            <p>FortiOS .conf backup files</p>
            <div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:center;margin-top:4px">
                <span class="fw-badge fw-badge-warn">FortiOS 6.x/7.x</span>
                <span class="fw-badge fw-badge-warn">.conf .txt</span>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height:24px'></div>", unsafe_allow_html=True)

    # Upload zone
    st.markdown(
        """
    <div class="fw-section-header">
        <div class="dot"></div>
        Upload Configuration
    </div>
    """,
        unsafe_allow_html=True,
    )

    uploaded = st.file_uploader(
        "Drag & drop your firewall backup here, or click to browse",
        type=["xml", "conf", "txt"],
        help="Supported: Palo Alto .xml exports | FortiGate .conf / .txt exports",
        label_visibility="visible",
    )

    if uploaded is None:
        st.markdown(
            """
        <div style="text-align:center;padding:16px;color:#8b949e;font-size:13px">
            <div style="display:flex;align-items:center;justify-content:center;gap:16px;
                        flex-wrap:wrap;margin-top:8px">
                <span>📂 Max file size: 50 MB</span>
                <span>•</span>
                <span>🔒 Files processed in-memory only</span>
                <span>•</span>
                <span>🗑️ Config cleared on session end</span>
            </div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    return uploaded


# ── Progress bar while parsing ────────────────────────────────────────────────
def show_parse_progress(filename: str):
    steps = [
        "Reading file...",
        "Parsing XML structure...",
        "Extracting policies...",
        "Resolving objects...",
        "Building index...",
        "Ready ✓",
    ]
    prog = st.progress(0, text=f"⚙️ Parsing `{filename}`")
    for i, step in enumerate(steps):
        time.sleep(0.12)
        prog.progress((i + 1) / len(steps), text=f"⚙️ {step}")
    time.sleep(0.1)
    prog.empty()


# ── Security: sanitize file content ──────────────────────────────────────────
def sanitize_upload(uploaded_file) -> bytes | None:
    """
    Basic security checks on uploaded file:
    - Size limit (50 MB)
    - Extension whitelist
    - No executable signatures
    """
    MAX_MB = 50
    ALLOWED_EXTS = {".xml", ".conf", ".txt"}
    FORBIDDEN_SIGS = [
        b"<script",  # XSS in XML
        b"<?php",  # PHP injection
        b"#!/",  # Shell scripts
        b"\x4d\x5a",  # PE executable (MZ)
        b"\x7fELF",  # ELF executable
    ]

    name = uploaded_file.name.lower()
    ext = Path(name).suffix

    if ext not in ALLOWED_EXTS:
        st.error(f"❌ File type `{ext}` not allowed. Use: {', '.join(ALLOWED_EXTS)}")
        return None

    content = uploaded_file.read()

    if len(content) > MAX_MB * 1024 * 1024:
        st.error(f"❌ File exceeds {MAX_MB} MB limit.")
        return None

    content_lower = content[:512].lower()
    for sig in FORBIDDEN_SIGS:
        if sig in content_lower:
            st.error("❌ File content failed security check.")
            return None

    return content


# ── Main app ──────────────────────────────────────────────────────────────────
def main():
    # Initialize theme
    if "theme" not in st.session_state:
        st.session_state.theme = "dark"

    # Auth gate
    if not require_auth():
        return

    # Inject CSS
    inject_css()

    # Topbar
    render_topbar()

    # ── Route based on loaded config ──────────────────
    if "parsed_data" not in st.session_state:
        # Landing page
        render_sidebar(None)
        uploaded = render_landing()

        if uploaded:
            content = sanitize_upload(uploaded)
            if content:
                show_parse_progress(uploaded.name)
                st.session_state.raw_content = content
                st.session_state.filename = uploaded.name
                # Detect vendor
                name_lower = uploaded.name.lower()
                if name_lower.endswith(".xml"):
                    st.session_state.vendor = "Palo Alto"
                else:
                    st.session_state.vendor = "FortiGate"
                st.session_state.parsed_data = True
                st.rerun()
    else:
        vendor = st.session_state.get("vendor", "Unknown")
        render_sidebar(vendor)

        # ── Action bar ────────────────────────────────
        col_title, col_badge, col_btn = st.columns([6, 2, 2])
        with col_title:
            st.markdown(
                f"""
            <div class="fw-section-header">
                <div class="dot"></div>
                {vendor} — {st.session_state.get('filename','config')}
            </div>
            """,
                unsafe_allow_html=True,
            )
        with col_badge:
            st.markdown(
                f"""
            <div style="padding-top:8px">
                <span class="fw-badge fw-badge-allow">
                    <span class="status-dot-live"></span> Loaded
                </span>
            </div>
            """,
                unsafe_allow_html=True,
            )
        with col_btn:
            st.markdown(
                '<div style="display:flex;justify-content:flex-end;padding-top:4px">',
                unsafe_allow_html=True,
            )
            if st.button("⬅ New Config", key="unload_btn"):
                for k in ["parsed_data", "raw_content", "filename", "vendor"]:
                    st.session_state.pop(k, None)
                st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)

        # ── Load actual parsers & render ──────────────
        try:
            content = st.session_state.raw_content

            if vendor == "Palo Alto":
                import xml.etree.ElementTree as ET
                from parsers.palo_policies import PaloPoliciesParser
                from parsers.palo_objects import PaloObjectsParser
                from parsers.palo_network import PaloNetworkParser
                from parsers.palo_device import PaloDeviceParser
                from parsers.palo_dashboard import PaloDashboardParser

                from views.palo_policies_views import render_pa_policies
                from views.palo_objects_views import render_pa_objects
                from views.palo_network_views import render_pa_network
                from views.palo_device_views import render_pa_device
                from views.palo_dashboard_views import render_pa_dashboard

                root = ET.fromstring(content.decode("utf-8", errors="replace"))

                main_tabs = st.tabs(
                    [
                        "🏠 Dashboard",
                        "📋 Policies",
                        "📦 Objects",
                        "🌐 Network",
                        "⚙️ Device",
                    ]
                )
                with main_tabs[0]:
                    render_pa_dashboard(PaloDashboardParser(root))
                with main_tabs[1]:
                    render_pa_policies(PaloPoliciesParser(root))
                with main_tabs[2]:
                    render_pa_objects(PaloObjectsParser(root))
                with main_tabs[3]:
                    render_pa_network(PaloNetworkParser(root))
                with main_tabs[4]:
                    render_pa_device(PaloDeviceParser(root))

            else:  # FortiGate
                text = content.decode("utf-8", errors="replace")
                from parsers.fortigate import FortiGateParser
                from views.summary_view import render_summary
                from views.interface_view import render_interfaces
                from views.network_view import render_network
                from views.policy_objects_view import render_policy_objects
                from views.security_view import render_security
                from views.vpn_view import render_vpn
                from views.user_view import render_user_auth
                from views.wifi_view import render_wifi
                from views.system_view import render_system
                from views.policy_lookup_view import render_policy_lookup
                from views.log_settings_view import render_log_settings

                fg = FortiGateParser(text)

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
                        "📊 Log & Report",
                    ]
                )
                with main_tabs[0]:
                    render_summary(fg)
                with main_tabs[1]:
                    render_interfaces(fg.parse_interfaces(), "FortiGate")
                with main_tabs[2]:
                    render_network(fg)
                with main_tabs[3]:
                    render_policy_objects(fg)
                with main_tabs[4]:
                    render_security(fg)
                with main_tabs[5]:
                    render_vpn(fg)
                with main_tabs[6]:
                    render_user_auth(fg)
                with main_tabs[7]:
                    render_wifi(fg)
                with main_tabs[8]:
                    render_system(fg)
                with main_tabs[9]:
                    render_log_settings(fg)

        except Exception as e:
            st.error(f"❌ Error loading config: {e}")
            import traceback

            with st.expander("🔍 Error details"):
                st.code(traceback.format_exc())


if __name__ == "__main__":
    main()
