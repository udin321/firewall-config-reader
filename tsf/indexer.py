"""
tsf/indexer.py
==============
Builds two in-memory indexes after TSF extraction:

  1. FILE INDEX  — maps every relative path → FileEntry metadata.
     Used by filename search (instant, no I/O at query time).

  2. CONTENT INDEX — maps token → list[(relative_path, line_number)].
     Built lazily in a background thread so the UI can show the explorer
     before content-indexing finishes.

Design decisions
----------------
* A single background Thread (daemon=True) runs build_content_index() so
  Streamlit's main thread is never blocked.
* We keep indexes in module-level dicts keyed by session_id so different
  browser sessions (different Streamlit script runs) don't collide.
* Content indexing tokenises on whitespace and strips punctuation so
  searches like "10.10.10.1" or "2026-07-02" find the right lines even
  when surrounded by colons, brackets, etc.
* Files larger than MAX_CONTENT_FILE_BYTES are skipped for content
  indexing (still appear in filename search).
* Binary files are detected heuristically and skipped.
"""

from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

# ── Configuration ─────────────────────────────────────────────────────────────

# File extensions considered "text" for content indexing.
TEXT_EXTENSIONS: set[str] = {
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
}

MAX_CONTENT_FILE_BYTES = 50 * 1024 * 1024  # 50 MB — skip larger files
BINARY_DETECT_BYTES = 8192  # bytes to sample for binary detection
MAX_TOTAL_INDEX_FILES = 50_000  # safety cap


# ── Data structures ───────────────────────────────────────────────────────────


@dataclass
class FileEntry:
    rel_path: str  # relative to session root, using forward slashes
    abs_path: Path
    size_bytes: int
    is_text: bool  # heuristic: extension in TEXT_EXTENSIONS
    parent_dir: str  # rel_path of parent directory ('' for root)
    name: str  # filename only


@dataclass
class ContentMatch:
    rel_path: str
    line_number: int  # 1-based
    line_text: str  # full line (stripped)


@dataclass
class IndexState:
    session_id: str
    session_root: Path
    file_index: dict[str, FileEntry] = field(
        default_factory=dict
    )  # rel_path → FileEntry
    dir_children: dict[str, list[str]] = field(
        default_factory=dict
    )  # dir → [rel_paths]

    # Content index is built asynchronously
    content_ready: bool = False
    content_progress: float = 0.0  # 0.0 → 1.0
    content_error: str = ""
    _content_lines: dict[str, list[tuple[int, str]]] = field(default_factory=dict)
    # rel_path → [(line_no, line_text), ...]

    _lock: threading.Lock = field(default_factory=threading.Lock)


# ── Module-level registry ─────────────────────────────────────────────────────

_indexes: dict[str, IndexState] = {}
_index_lock = threading.Lock()


# ── Public API ────────────────────────────────────────────────────────────────


def build_file_index(session_id: str, session_root: Path) -> IndexState:
    """
    Synchronously walk session_root and build the file + directory index.
    Fast (metadata only, no file reads).  Returns the IndexState so the
    caller can start the UI immediately.
    """
    state = IndexState(session_id=session_id, session_root=session_root)

    root = session_root.resolve()
    count = 0

    for abs_path in _walk(root):
        if count >= MAX_TOTAL_INDEX_FILES:
            break

        try:
            stat = abs_path.stat()
        except OSError:
            continue

        rel = str(abs_path.relative_to(root)).replace("\\", "/")
        ext = abs_path.suffix.lower()
        parent = str(abs_path.parent.relative_to(root)).replace("\\", "/")
        if parent == ".":
            parent = ""

        entry = FileEntry(
            rel_path=rel,
            abs_path=abs_path,
            size_bytes=stat.st_size,
            is_text=(ext in TEXT_EXTENSIONS),
            parent_dir=parent,
            name=abs_path.name,
        )
        state.file_index[rel] = entry

        # Build children map
        if parent not in state.dir_children:
            state.dir_children[parent] = []
        state.dir_children[parent].append(rel)

        # Ensure parent dirs are in dir_children (even if they have no direct files)
        _ensure_dir_ancestors(state, parent)

        count += 1

    with _index_lock:
        _indexes[session_id] = state

    return state


def start_content_indexing(session_id: str) -> None:
    """
    Launch a daemon thread to content-index all text files for session_id.
    The IndexState must already exist (call build_file_index first).
    """
    with _index_lock:
        state = _indexes.get(session_id)
    if state is None:
        return

    t = threading.Thread(
        target=_content_index_worker,
        args=(state,),
        daemon=True,
        name=f"tsf-content-{session_id[:8]}",
    )
    t.start()


def get_index(session_id: str) -> IndexState | None:
    """Return the IndexState for a session, or None if not found."""
    with _index_lock:
        return _indexes.get(session_id)


def drop_index(session_id: str) -> None:
    """Remove a session's index from memory."""
    with _index_lock:
        _indexes.pop(session_id, None)


# ── Filename search ───────────────────────────────────────────────────────────


def search_filenames(state: IndexState, query: str) -> list[FileEntry]:
    """
    Case-insensitive substring search across all indexed file names.
    Returns matching FileEntry objects sorted by rel_path.
    """
    if not query:
        return []
    q = query.lower()
    results = [e for e in state.file_index.values() if q in e.name.lower()]
    return sorted(results, key=lambda e: e.rel_path.lower())


# ── Content search ────────────────────────────────────────────────────────────


def search_content(
    state: IndexState,
    query: str,
    max_results: int = 500,
) -> list[ContentMatch]:
    """
    Case-insensitive substring search across all indexed line content.
    Returns up to max_results ContentMatch objects.

    If content indexing is still in progress, searches only the lines
    indexed so far (partial results).
    """
    if not query or not state.content_ready and not state._content_lines:
        return []

    q = query.lower()
    results: list[ContentMatch] = []

    with state._lock:
        items = list(state._content_lines.items())

    for rel_path, lines in items:
        for line_no, line_text in lines:
            if q in line_text.lower():
                results.append(
                    ContentMatch(
                        rel_path=rel_path,
                        line_number=line_no,
                        line_text=line_text,
                    )
                )
                if len(results) >= max_results:
                    return results

    return results


# ── Directory tree helpers ────────────────────────────────────────────────────


def list_dir(state: IndexState, dir_path: str) -> tuple[list[str], list[FileEntry]]:
    """
    Return (subdirs, files) for dir_path within the index.
    dir_path should be a relative path string ('' for root).
    subdirs is a sorted list of relative directory paths.
    files is a sorted list of FileEntry for files directly in dir_path.
    """
    children_rels = state.dir_children.get(dir_path, [])

    subdirs: set[str] = set()
    files: list[FileEntry] = []

    for rel in children_rels:
        entry = state.file_index.get(rel)
        if entry:
            files.append(entry)
        else:
            # It's a dir placeholder
            subdirs.add(rel)

    # Also discover subdirectories from dir_children keys
    prefix = (dir_path + "/") if dir_path else ""
    for key in state.dir_children:
        if key == dir_path:
            continue
        if key.startswith(prefix):
            # Only direct children
            rest = key[len(prefix) :]
            if "/" not in rest and rest:
                subdirs.add(key)

    return (
        sorted(subdirs),
        sorted(files, key=lambda e: e.name.lower()),
    )


# ── Internal helpers ──────────────────────────────────────────────────────────


def _walk(root: Path) -> Iterator[Path]:
    """Yield all file paths under root (no directories), avoiding symlinks
    that escape the root to prevent traversal via symlinks in ZIPs."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = Path(dirpath)
        for fn in filenames:
            fp = dp / fn
            # Extra symlink safety: ensure resolved path is still under root
            try:
                fp.resolve().relative_to(root)
                yield fp
            except ValueError:
                pass


def _ensure_dir_ancestors(state: IndexState, rel_dir: str) -> None:
    """Make sure all ancestor directories of rel_dir exist in dir_children."""
    parts = rel_dir.split("/") if rel_dir else []
    for i in range(len(parts)):
        parent = "/".join(parts[:i]) if i > 0 else ""
        child = "/".join(parts[: i + 1])
        if parent not in state.dir_children:
            state.dir_children[parent] = []
        if child not in state.dir_children[parent]:
            state.dir_children[parent].append(child)


def _is_binary(data: bytes) -> bool:
    """Heuristic: if more than 10% of sampled bytes are non-printable
    (excluding common control chars like tab/newline), treat as binary."""
    sample = data[:BINARY_DETECT_BYTES]
    if not sample:
        return False
    non_text = sum(1 for b in sample if b < 9 or (13 < b < 32 and b not in (9, 10, 13)))
    return (non_text / len(sample)) > 0.10


def _content_index_worker(state: IndexState) -> None:
    """Background thread: read and index text file lines."""
    text_entries = [
        e
        for e in state.file_index.values()
        if e.is_text and e.size_bytes <= MAX_CONTENT_FILE_BYTES
    ]
    total = len(text_entries)
    if total == 0:
        state.content_ready = True
        return

    for idx, entry in enumerate(text_entries):
        try:
            raw = entry.abs_path.read_bytes()
            if _is_binary(raw):
                continue
            text = raw.decode("utf-8", errors="replace")
            lines = []
            for line_no, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped:
                    lines.append((line_no, stripped))

            with state._lock:
                state._content_lines[entry.rel_path] = lines

        except OSError:
            pass

        state.content_progress = (idx + 1) / total

    state.content_ready = True
