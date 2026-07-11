"""
tsf/file_preview.py
===================
Reads a single file from the TSF session directory and returns its content
in a safe, paginated form for display in the viewer panel.

Design decisions
----------------
* We read at most MAX_READ_BYTES from any file regardless of its reported
  size, so a maliciously-large or accidentally-huge log file cannot OOM
  the Streamlit server.
* Binary files (detected heuristically) are refused with a friendly
  message rather than garbled output.
* The returned PreviewResult carries pages: list[list[str]] — a list of
  pages, each page being a list of lines.  The UI can render one page at
  a time without holding the entire file in memory as a rendered widget.
* Line numbers are 1-based and returned alongside the content so the UI
  can jump to a specific line (e.g. from a content-search result).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────

MAX_READ_BYTES = 10 * 1024 * 1024  # 10 MB hard read cap per file
LINES_PER_PAGE = 500  # lines shown per paginated page

# Extensions we will attempt to render as text
VIEWABLE_EXTENSIONS: set[str] = {
    ".txt",
    ".log",
    ".xml",
    ".cfg",
    ".conf",
    ".csv",
    ".json",
    ".out",
    ".html",
    ".htm",
    ".ini",
    ".yaml",
    ".yml",
    ".sh",
    ".py",
    ".md",
    ".rst",
    ".tsv",
    ".properties",
    ".env",
    ".text",
    ".lst",
    ".dat",
}

BINARY_DETECT_BYTES = 8192  # bytes sampled for binary detection


# ── Data structures ───────────────────────────────────────────────────────────


@dataclass
class PreviewResult:
    success: bool
    is_binary: bool = False
    truncated: bool = False  # True when file was cut at MAX_READ_BYTES
    total_lines: int = 0
    total_pages: int = 0
    pages: list[list[tuple[int, str]]] = field(default_factory=list)
    # Each page is a list of (line_number, line_text) tuples, 1-based.
    error: str = ""
    file_size_bytes: int = 0
    encoding: str = "utf-8"


# ── Public API ────────────────────────────────────────────────────────────────


def preview_file(
    abs_path: Path,
    lines_per_page: int = LINES_PER_PAGE,
) -> PreviewResult:
    """
    Read abs_path safely and return a PreviewResult.

    Always safe to call — never raises; errors are captured in result.error.
    """
    # ── Extension check ───────────────────────────────────────────────────
    ext = abs_path.suffix.lower()
    if ext and ext not in VIEWABLE_EXTENSIONS:
        return PreviewResult(
            success=False,
            is_binary=True,
            error=f"This file type ({ext}) cannot be previewed.",
            file_size_bytes=_safe_size(abs_path),
        )

    # ── Read bytes ────────────────────────────────────────────────────────
    try:
        file_size = abs_path.stat().st_size
    except OSError as exc:
        return PreviewResult(success=False, error=f"Cannot stat file: {exc}")

    try:
        raw = abs_path.read_bytes()
    except OSError as exc:
        return PreviewResult(
            success=False, error=f"Cannot read file: {exc}", file_size_bytes=file_size
        )

    truncated = False
    if len(raw) > MAX_READ_BYTES:
        raw = raw[:MAX_READ_BYTES]
        truncated = True

    # ── Binary detection ──────────────────────────────────────────────────
    if _is_binary(raw):
        return PreviewResult(
            success=False,
            is_binary=True,
            error="This file type cannot be previewed.",
            file_size_bytes=file_size,
        )

    # ── Decode ────────────────────────────────────────────────────────────
    encoding = "utf-8"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
            encoding = "latin-1"
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            encoding = "utf-8 (lossy)"

    # ── Split into lines ──────────────────────────────────────────────────
    all_lines: list[tuple[int, str]] = [
        (i + 1, line) for i, line in enumerate(text.splitlines())
    ]
    total_lines = len(all_lines)

    # ── Paginate ──────────────────────────────────────────────────────────
    pages: list[list[tuple[int, str]]] = []
    lpp = max(1, lines_per_page)
    for start in range(0, max(1, total_lines), lpp):
        pages.append(all_lines[start : start + lpp])

    if not pages:
        pages = [[]]  # always at least one page (empty file)

    return PreviewResult(
        success=True,
        truncated=truncated,
        total_lines=total_lines,
        total_pages=len(pages),
        pages=pages,
        file_size_bytes=file_size,
        encoding=encoding,
    )


def page_containing_line(result: PreviewResult, line_number: int) -> int:
    """Return the 0-based page index that contains the given 1-based line."""
    for page_idx, page in enumerate(result.pages):
        if any(ln == line_number for ln, _ in page):
            return page_idx
    return 0


# ── Helpers ───────────────────────────────────────────────────────────────────


def _is_binary(data: bytes) -> bool:
    """Heuristic binary detection: >10% non-printable bytes → binary."""
    sample = data[:BINARY_DETECT_BYTES]
    if not sample:
        return False
    non_text = sum(1 for b in sample if b < 9 or (13 < b < 32 and b not in (9, 10, 13)))
    return (non_text / len(sample)) > 0.10


def _safe_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def human_size(size_bytes: int) -> str:
    """Convert byte count to a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
