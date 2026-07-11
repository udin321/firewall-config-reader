"""
views/tsf_explorer.py
=====================
The TSF Explorer page rendered inside the existing app.py shell.

Layout
------
  ┌─ topbar (inherited from app.py) ──────────────────────────────────┐
  │  Search bar (filename / content toggle)                            │
  ├──────────────────┬─────────────────────────────────────────────────┤
  │  Directory tree  │  File content viewer  OR  Search results        │
  │  (left panel)   │  (right panel)                                  │
  └──────────────────┴─────────────────────────────────────────────────┘

State keys used (all namespaced with "tsf_")
--------------------------------------------
  tsf_open_dirs  : set of rel_path strings for expanded directories
  tsf_open_file  : rel_path of currently-open file (or "")
  tsf_preview    : cached PreviewResult for the open file
  tsf_page       : current page index (0-based) in paginated viewer
  tsf_jump_line  : 1-based line number to jump to after opening a file
  tsf_search_q   : last search query string
  tsf_search_mode: "filename" | "content"
  tsf_fn_results : list[FileEntry] from last filename search
  tsf_ct_results : list[ContentMatch] from last content search
"""

from __future__ import annotations

import html
from pathlib import Path

import streamlit as st

from tsf.indexer import (
    IndexState,
    FileEntry,
    ContentMatch,
    list_dir,
    search_filenames,
    search_content,
)
from tsf.file_preview import preview_file, page_containing_line, human_size

# ── colour aliases (read from current theme each render) ──────────────────────


def _pal():
    theme = st.session_state.get("theme", "dark")
    if theme == "dark":
        return {
            "bg": "#0d1117",
            "panel": "#161b22",
            "border": "#30363d",
            "text": "#e6edf3",
            "dim": "#8b949e",
            "accent": "#3a7bd5",
            "accent2": "#58a6ff",
            "success": "#3fb950",
            "warn": "#d29922",
            "danger": "#f85149",
            "hover": "#21262d",
            "selected": "#1f3555",
            "code_bg": "#0d1117",
            "scrollbar": "#30363d",
        }
    return {
        "bg": "#f6f8fa",
        "panel": "#ffffff",
        "border": "#d0d7de",
        "text": "#1f2328",
        "dim": "#656d76",
        "accent": "#0969da",
        "accent2": "#0550ae",
        "success": "#1a7f37",
        "warn": "#9a6700",
        "danger": "#cf222e",
        "hover": "#f3f4f6",
        "selected": "#dbeafe",
        "code_bg": "#f6f8fa",
        "scrollbar": "#d0d7de",
    }


# ── Session state initialisation ─────────────────────────────────────────────


def _init_state():
    defaults = {
        "tsf_open_dirs": set(),
        "tsf_open_file": "",
        "tsf_preview": None,
        "tsf_page": 0,
        "tsf_jump_line": 0,
        "tsf_search_q": "",
        "tsf_search_mode": "filename",
        "tsf_fn_results": [],
        "tsf_ct_results": [],
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# ── CSS ───────────────────────────────────────────────────────────────────────


def _inject_tsf_css():
    p = _pal()
    st.markdown(
        f"""
<style>
/* ── TSF Explorer layout ─────────────────── */
.tsf-header {{
    display:flex; align-items:center; gap:12px;
    padding:10px 0 16px;
    border-bottom:1px solid {p['border']};
    margin-bottom:14px;
}}
.tsf-badge {{
    background:{p['accent']}22; color:{p['accent2']};
    border:1px solid {p['accent']}44;
    border-radius:20px; padding:3px 12px;
    font-size:11px; font-weight:700; letter-spacing:.4px;
}}
.tsf-stats {{
    color:{p['dim']}; font-size:12px;
}}

/* ── Search bar ─────────────────────────── */
.tsf-search-wrap {{
    background:{p['panel']};
    border:1px solid {p['border']};
    border-radius:10px; padding:12px 16px;
    margin-bottom:14px;
}}

/* ── Directory tree ─────────────────────── */
.tsf-tree-node {{
    display:flex; align-items:center; gap:6px;
    padding:4px 6px; border-radius:6px;
    cursor:pointer; font-size:13px;
    color:{p['text']}; white-space:nowrap;
    overflow:hidden; text-overflow:ellipsis;
    transition:background .12s;
}}
.tsf-tree-node:hover {{ background:{p['hover']}; }}
.tsf-tree-node.selected {{ background:{p['selected']}; color:{p['accent2']}; }}
.tsf-tree-dir  {{ font-weight:600; }}
.tsf-tree-file {{ opacity:.9; }}
.tsf-tree-icon {{ flex-shrink:0; font-size:14px; }}

/* ── File viewer ─────────────────────────── */
.tsf-viewer-header {{
    display:flex; align-items:center; justify-content:space-between;
    padding:8px 12px; background:{p['panel']};
    border:1px solid {p['border']}; border-radius:10px 10px 0 0;
    margin-bottom:0;
}}
.tsf-viewer-meta {{ font-size:11px; color:{p['dim']}; }}
.tsf-code-wrap {{
    background:{p['code_bg']};
    border:1px solid {p['border']}; border-top:none;
    border-radius:0 0 10px 10px;
    overflow-x:auto; overflow-y:auto;
    max-height:62vh;
    font-family:'JetBrains Mono','Fira Code','Cascadia Code',monospace;
    font-size:12.5px; line-height:1.6;
}}
.tsf-code-table {{ border-collapse:collapse; width:100%; }}
.tsf-line {{ display:flex; }}
.tsf-ln {{
    min-width:52px; padding:0 12px 0 8px;
    color:{p['dim']}; text-align:right;
    user-select:none; border-right:1px solid {p['border']};
    flex-shrink:0;
}}
.tsf-lc {{ padding:0 12px; color:{p['text']}; white-space:pre; flex:1; }}
.tsf-lc.hl {{ background:{p['warn']}33; border-left:3px solid {p['warn']}; padding-left:9px; }}

/* ── Search results ──────────────────────── */
.tsf-result-card {{
    background:{p['panel']};
    border:1px solid {p['border']};
    border-radius:10px; padding:12px 14px;
    margin-bottom:8px; cursor:pointer;
    transition:border-color .15s, box-shadow .15s;
}}
.tsf-result-card:hover {{
    border-color:{p['accent']}66;
    box-shadow:0 0 0 3px {p['accent']}11;
}}
.tsf-result-file {{ font-weight:700; color:{p['text']}; font-size:13px; }}
.tsf-result-dir  {{ font-size:11px; color:{p['dim']}; margin-top:2px; }}
.tsf-result-line {{
    background:{p['code_bg']};
    border-left:3px solid {p['accent']};
    padding:4px 10px; margin-top:6px;
    font-family:monospace; font-size:12px;
    color:{p['text']}; border-radius:0 6px 6px 0;
    white-space:pre-wrap; word-break:break-all;
}}
.tsf-result-lineno {{ color:{p['dim']}; font-size:11px; margin-top:3px; }}
.tsf-highlight {{ background:{p['warn']}55; border-radius:2px; padding:0 2px; }}

/* ── Index progress ──────────────────────── */
.tsf-index-banner {{
    background:{p['warn']}18; border:1px solid {p['warn']}44;
    border-radius:8px; padding:8px 14px; margin-bottom:10px;
    color:{p['warn']}; font-size:12px;
    display:flex; align-items:center; gap:8px;
}}

/* ── Empty state ─────────────────────────── */
.tsf-empty {{
    text-align:center; padding:40px 20px;
    color:{p['dim']}; font-size:14px;
}}
.tsf-empty-icon {{ font-size:36px; margin-bottom:8px; }}

/* ── Scrollbar ───────────────────────────── */
.tsf-code-wrap::-webkit-scrollbar {{ width:6px; height:6px; }}
.tsf-code-wrap::-webkit-scrollbar-thumb {{
    background:{p['scrollbar']}; border-radius:3px;
}}
</style>
""",
        unsafe_allow_html=True,
    )


# ── Main entry point ──────────────────────────────────────────────────────────


def render_tsf_explorer(state: IndexState):
    """Called from app.py when tsf_session is active."""
    _init_state()
    _inject_tsf_css()
    p = _pal()

    session_root = state.session_root
    total_files = len(state.file_index)

    # ── Page header ───────────────────────────────────────────────────────
    st.markdown(
        f"""<div class="tsf-header">
            <span style="font-size:22px">🗂️</span>
            <span style="font-size:20px;font-weight:800;color:{p['text']}">TSF Explorer</span>
            <span class="tsf-badge">Palo Alto Technical Support File</span>
            <span class="tsf-stats">{total_files:,} files indexed</span>
        </div>""",
        unsafe_allow_html=True,
    )

    # ── Content-index progress banner ─────────────────────────────────────
    if not state.content_ready:
        pct = int(state.content_progress * 100)
        st.markdown(
            f'<div class="tsf-index-banner">⏳ Content indexing in progress… {pct}% — '
            f"content search will be available shortly.</div>",
            unsafe_allow_html=True,
        )

    # ── Search bar ────────────────────────────────────────────────────────
    _render_search_bar(state, p)

    # ── Main two-column layout ────────────────────────────────────────────
    tree_col, viewer_col = st.columns([1, 2], gap="small")

    with tree_col:
        _render_tree_panel(state, session_root, p)

    with viewer_col:
        # Show search results if a search was run, else file viewer
        if st.session_state.tsf_search_q:
            _render_search_results(state, p)
        else:
            _render_file_viewer(p)


# ── Search bar ────────────────────────────────────────────────────────────────


def _render_search_bar(state: IndexState, p: dict):
    with st.container():
        col_mode, col_input, col_btn, col_clear = st.columns([2, 6, 1, 1])

        with col_mode:
            mode = st.selectbox(
                "Mode",
                ["filename", "content"],
                index=0 if st.session_state.tsf_search_mode == "filename" else 1,
                key="tsf_mode_select",
                label_visibility="collapsed",
            )
            st.session_state.tsf_search_mode = mode

        placeholder = (
            "Search files by filename…"
            if mode == "filename"
            else "Search file contents (IP, keyword, date…)"
        )

        with col_input:
            query = st.text_input(
                "Search",
                value=st.session_state.tsf_search_q,
                placeholder=placeholder,
                key="tsf_search_input",
                label_visibility="collapsed",
            )

        with col_btn:
            run = st.button("🔍", key="tsf_search_btn", help="Run search")

        with col_clear:
            if st.button("✕", key="tsf_search_clear", help="Clear search"):
                st.session_state.tsf_search_q = ""
                st.session_state.tsf_fn_results = []
                st.session_state.tsf_ct_results = []
                st.rerun()

        if run and query.strip():
            _run_search(state, query.strip())


def _run_search(state: IndexState, query: str):
    st.session_state.tsf_search_q = query
    if st.session_state.tsf_search_mode == "filename":
        with st.spinner("Searching filenames…"):
            st.session_state.tsf_fn_results = search_filenames(state, query)
        st.session_state.tsf_ct_results = []
    else:
        if not state.content_ready and not state._content_lines:
            st.warning("⏳ Content indexing hasn't started yet. Please wait a moment.")
            return
        with st.spinner("Searching file contents…"):
            st.session_state.tsf_ct_results = search_content(
                state, query, max_results=500
            )
        st.session_state.tsf_fn_results = []
    st.rerun()


# ── Directory tree panel ──────────────────────────────────────────────────────


def _render_tree_panel(state: IndexState, session_root: Path, p: dict):
    st.markdown(
        f'<div style="font-size:12px;font-weight:700;color:{p["dim"]};'
        f'text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">'
        f"📁 Directory Tree</div>",
        unsafe_allow_html=True,
    )

    with st.container(height=520, border=False):
        _render_dir_node(state, dir_path="", depth=0, p=p)


def _render_dir_node(state: IndexState, dir_path: str, depth: int, p: dict):
    """Recursively render directory nodes."""
    subdirs, files = list_dir(state, dir_path)

    indent_px = depth * 16

    for subdir in subdirs:
        dir_name = subdir.rsplit("/", 1)[-1] if "/" in subdir else subdir
        is_open = subdir in st.session_state.tsf_open_dirs
        icon = "📂" if is_open else "📁"

        col_btn, col_label = st.columns([1, 8], gap="small")
        with col_btn:
            st.markdown(
                f'<div style="padding-left:{indent_px}px"></div>',
                unsafe_allow_html=True,
            )
        with col_label:
            if st.button(
                f"{icon} {dir_name}",
                key=f"dir_{subdir}",
                use_container_width=True,
                help=subdir,
            ):
                if is_open:
                    st.session_state.tsf_open_dirs.discard(subdir)
                else:
                    st.session_state.tsf_open_dirs.add(subdir)
                st.rerun()

        if is_open:
            _render_dir_node(state, dir_path=subdir, depth=depth + 1, p=p)

    for entry in files:
        ext = Path(entry.name).suffix.lower()
        icon = _file_icon(ext)
        is_selected = entry.rel_path == st.session_state.tsf_open_file

        label = f"{icon} {entry.name}"
        key = f"file_{entry.rel_path}"

        col_pad, col_file = st.columns([1, 8], gap="small")
        with col_pad:
            st.markdown(
                f'<div style="padding-left:{indent_px + 16}px"></div>',
                unsafe_allow_html=True,
            )
        with col_file:
            btn_style = (
                f"background:{p['selected']}; color:{p['accent2']}; font-weight:600;"
                if is_selected
                else ""
            )
            if st.button(
                label,
                key=key,
                use_container_width=True,
                help=f"{entry.rel_path} ({human_size(entry.size_bytes)})",
            ):
                _open_file(entry.abs_path, entry.rel_path, jump_line=0)


def _open_file(abs_path: Path, rel_path: str, jump_line: int = 0):
    """Load a file for preview and switch the viewer to it."""
    result = preview_file(abs_path)
    st.session_state.tsf_open_file = rel_path
    st.session_state.tsf_preview = result
    st.session_state.tsf_jump_line = jump_line
    # Set the page to the one containing the target line
    if jump_line > 0 and result.success:
        st.session_state.tsf_page = page_containing_line(result, jump_line)
    else:
        st.session_state.tsf_page = 0
    # Clear search so viewer panel is shown
    st.session_state.tsf_search_q = ""
    st.rerun()


# ── File viewer panel ─────────────────────────────────────────────────────────


def _render_file_viewer(p: dict):
    open_file = st.session_state.tsf_open_file
    preview = st.session_state.tsf_preview

    if not open_file or preview is None:
        st.markdown(
            f'<div class="tsf-empty">'
            f'<div class="tsf-empty-icon">📄</div>'
            f"Select a file from the directory tree to preview its contents."
            f"</div>",
            unsafe_allow_html=True,
        )
        return

    file_name = Path(open_file).name
    p_obj = Path(open_file)

    # ── Viewer header ─────────────────────────────────────────────────────
    col_name, col_meta = st.columns([3, 2])
    with col_name:
        st.markdown(
            f'<div style="font-weight:700;font-size:14px;color:{p["text"]}">'
            f"📄 {html.escape(file_name)}</div>"
            f'<div style="font-size:11px;color:{p["dim"]}">{html.escape(open_file)}</div>',
            unsafe_allow_html=True,
        )
    with col_meta:
        if preview.success:
            st.markdown(
                f'<div class="tsf-viewer-meta">'
                f"{human_size(preview.file_size_bytes)} · "
                f"{preview.total_lines:,} lines · "
                f"page {st.session_state.tsf_page + 1}/{preview.total_pages} · "
                f"{preview.encoding}"
                f'{"  ⚠️ truncated" if preview.truncated else ""}'
                f"</div>",
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    if not preview.success:
        st.markdown(
            f'<div style="padding:24px;text-align:center;color:{p["dim"]};'
            f'border:1px solid {p["border"]};border-radius:10px;">'
            f"🚫 {html.escape(preview.error)}</div>",
            unsafe_allow_html=True,
        )
        return

    # ── Pagination controls ───────────────────────────────────────────────
    if preview.total_pages > 1:
        pcol1, pcol2, pcol3, pcol4, pcol5 = st.columns([1, 1, 3, 1, 1])
        with pcol1:
            if st.button("⏮", key="tsf_page_first", help="First page"):
                st.session_state.tsf_page = 0
                st.rerun()
        with pcol2:
            if st.button("◀", key="tsf_page_prev", help="Previous page"):
                st.session_state.tsf_page = max(0, st.session_state.tsf_page - 1)
                st.rerun()
        with pcol3:
            new_page = st.slider(
                "Page",
                min_value=1,
                max_value=preview.total_pages,
                value=st.session_state.tsf_page + 1,
                key="tsf_page_slider",
                label_visibility="collapsed",
            )
            if new_page - 1 != st.session_state.tsf_page:
                st.session_state.tsf_page = new_page - 1
                st.rerun()
        with pcol4:
            if st.button("▶", key="tsf_page_next", help="Next page"):
                st.session_state.tsf_page = min(
                    preview.total_pages - 1, st.session_state.tsf_page + 1
                )
                st.rerun()
        with pcol5:
            if st.button("⏭", key="tsf_page_last", help="Last page"):
                st.session_state.tsf_page = preview.total_pages - 1
                st.rerun()

    # ── Render code block ─────────────────────────────────────────────────
    page_idx = min(st.session_state.tsf_page, preview.total_pages - 1)
    page_lines = preview.pages[page_idx] if preview.pages else []
    jump_line = st.session_state.tsf_jump_line

    lines_html = []
    for ln, text in page_lines:
        is_jump = jump_line > 0 and ln == jump_line
        hl_class = " hl" if is_jump else ""
        safe_text = html.escape(text)
        lines_html.append(
            f'<div class="tsf-line" id="tsf-ln-{ln}">'
            f'<span class="tsf-ln">{ln}</span>'
            f'<span class="tsf-lc{hl_class}">{safe_text}</span>'
            f"</div>"
        )

    code_html = "\n".join(lines_html)
    scroll_script = ""
    if jump_line > 0:
        scroll_script = f"""
        <script>
        const el = document.getElementById('tsf-ln-{jump_line}');
        if (el) el.scrollIntoView({{block:'center', behavior:'smooth'}});
        </script>
        """

    st.markdown(
        f'<div class="tsf-code-wrap">{code_html}</div>{scroll_script}',
        unsafe_allow_html=True,
    )


# ── Search results panel ──────────────────────────────────────────────────────


def _render_search_results(state: IndexState, p: dict):
    q = st.session_state.tsf_search_q
    mode = st.session_state.tsf_search_mode

    fn_results = st.session_state.tsf_fn_results
    ct_results = st.session_state.tsf_ct_results

    # ── Result count header ───────────────────────────────────────────────
    if mode == "filename":
        n = len(fn_results)
        st.markdown(
            f'<div style="font-size:13px;color:{p["dim"]};margin-bottom:10px">'
            f'🔍 <b>{n}</b> file{"s" if n != 1 else ""} matching '
            f"<code>{html.escape(q)}</code> by filename</div>",
            unsafe_allow_html=True,
        )
        if not fn_results:
            st.markdown(
                f'<div class="tsf-empty"><div class="tsf-empty-icon">🔎</div>'
                f"No files found matching <b>{html.escape(q)}</b></div>",
                unsafe_allow_html=True,
            )
            return

        for entry in fn_results:
            _render_filename_result(entry, q, state, p)

    else:  # content
        if not state.content_ready and not state._content_lines:
            st.info("⏳ Content indexing is still in progress. Try again in a moment.")
            return

        n = len(ct_results)
        limited = n >= 500
        st.markdown(
            f'<div style="font-size:13px;color:{p["dim"]};margin-bottom:10px">'
            f'🔍 <b>{n}{"+" if limited else ""}</b> match{"es" if n != 1 else ""} for '
            f"<code>{html.escape(q)}</code> in file contents"
            f'{"  (showing first 500)" if limited else ""}</div>',
            unsafe_allow_html=True,
        )
        if not ct_results:
            st.markdown(
                f'<div class="tsf-empty"><div class="tsf-empty-icon">🔎</div>'
                f"No matches found for <b>{html.escape(q)}</b></div>",
                unsafe_allow_html=True,
            )
            return

        # Group by file for cleaner display
        _render_content_results(ct_results, q, state, p)


def _render_filename_result(entry: "FileEntry", q: str, state: IndexState, p: dict):
    icon = _file_icon(Path(entry.name).suffix.lower())
    # Highlight query in filename
    hl_name = _highlight(entry.name, q)

    card_key = f"fn_res_{entry.rel_path}"
    if st.button(
        f"{icon}  {entry.name}",
        key=card_key,
        help=f"Open {entry.rel_path}",
        use_container_width=True,
    ):
        _open_file(entry.abs_path, entry.rel_path, jump_line=0)

    st.markdown(
        f'<div style="font-size:11px;color:{p["dim"]};margin:-8px 0 8px 8px">'
        f'📂 {html.escape(entry.parent_dir or "/")} · {human_size(entry.size_bytes)}'
        f"</div>",
        unsafe_allow_html=True,
    )


def _render_content_results(
    results: list["ContentMatch"],
    q: str,
    state: IndexState,
    p: dict,
):
    """Group content matches by file and render each group."""
    # Group: rel_path → list[ContentMatch]
    groups: dict[str, list] = {}
    for r in results:
        groups.setdefault(r.rel_path, []).append(r)

    for rel_path, matches in groups.items():
        entry = state.file_index.get(rel_path)
        if not entry:
            continue

        icon = _file_icon(Path(rel_path).suffix.lower())
        n = len(matches)
        dir_part = entry.parent_dir or "/"

        with st.expander(
            f"{icon} {entry.name}  ({n} match{'es' if n != 1 else ''})",
            expanded=(len(groups) <= 5),
        ):
            st.markdown(
                f'<div style="font-size:11px;color:{p["dim"]};margin-bottom:8px">'
                f"📂 {html.escape(dir_part)} · {human_size(entry.size_bytes)}</div>",
                unsafe_allow_html=True,
            )
            for m in matches[:20]:  # max 20 lines per file in the collapsed view
                hl_text = _highlight(m.line_text, q)
                btn_key = f"ct_{rel_path}_{m.line_number}"
                col_btn, col_text = st.columns([1, 6], gap="small")
                with col_btn:
                    if st.button(
                        f":{m.line_number}",
                        key=btn_key,
                        help=f"Jump to line {m.line_number}",
                    ):
                        _open_file(entry.abs_path, rel_path, jump_line=m.line_number)
                with col_text:
                    st.markdown(
                        f'<div class="tsf-result-line">{hl_text}</div>',
                        unsafe_allow_html=True,
                    )
            if n > 20:
                if st.button(
                    f"Open file to see all {n} matches →",
                    key=f"ct_open_{rel_path}",
                    use_container_width=True,
                ):
                    _open_file(
                        entry.abs_path, rel_path, jump_line=matches[0].line_number
                    )


# ── Utilities ─────────────────────────────────────────────────────────────────


def _highlight(text: str, query: str) -> str:
    """Wrap all case-insensitive occurrences of query in a highlight span.
    Returns HTML-escaped result."""
    import re

    safe_q = re.escape(query)
    parts = re.split(f"({safe_q})", text, flags=re.IGNORECASE)
    result = []
    for part in parts:
        if part.lower() == query.lower():
            result.append(f'<mark class="tsf-highlight">{html.escape(part)}</mark>')
        else:
            result.append(html.escape(part))
    return "".join(result)


def _file_icon(ext: str) -> str:
    mapping = {
        ".xml": "📋",
        ".json": "📊",
        ".log": "📜",
        ".csv": "📈",
        ".conf": "⚙️",
        ".cfg": "⚙️",
        ".txt": "📄",
        ".out": "📤",
        ".sh": "💻",
        ".py": "🐍",
        ".yml": "🔧",
        ".yaml": "🔧",
        ".html": "🌐",
        ".htm": "🌐",
        ".md": "📝",
        ".ini": "⚙️",
    }
    return mapping.get(ext, "📄")
