"""
tsf/search.py
=============
Thin convenience layer on top of tsf/indexer.py.

Why a separate file?
  - Keeps the indexer focused on data-structure construction.
  - Gives the UI a single, stable import for all search operations.
  - Houses the grouping / ranking logic that the UI needs but that doesn't
    belong inside the raw indexer.

Public API
----------
  search_by_filename(state, query)  → list[FileEntry]
  search_by_content(state, query)   → list[ContentGroup]
  ContentGroup                      — file + its matching lines, ranked
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tsf.indexer import (
    IndexState,
    FileEntry,
    ContentMatch,
    search_filenames,
    search_content,
)

# ── Data structures ───────────────────────────────────────────────────────────


@dataclass
class ContentGroup:
    """All content matches for a single file, ready for the UI to render."""

    entry: FileEntry
    matches: list[ContentMatch]
    total_lines: int = 0  # total matching lines in this file


# ── Public API ────────────────────────────────────────────────────────────────


def search_by_filename(state: IndexState, query: str) -> list[FileEntry]:
    """
    Case-insensitive substring search across all indexed file *names*
    (not full paths).  Results are sorted: exact-name matches first,
    then alphabetical by relative path.

    Returns [] immediately if query is empty or the index has no files.
    """
    if not query.strip() or not state.file_index:
        return []

    results = search_filenames(state, query.strip())

    # Rank: exact-name match first, then starts-with, then contains
    q = query.strip().lower()

    def _rank(e: FileEntry) -> tuple[int, str]:
        n = e.name.lower()
        if n == q:
            return (0, e.rel_path)
        if n.startswith(q):
            return (1, e.rel_path)
        return (2, e.rel_path)

    return sorted(results, key=_rank)


def search_by_content(
    state: IndexState,
    query: str,
    max_results: int = 500,
) -> list[ContentGroup]:
    """
    Case-insensitive substring search across all indexed file *contents*.
    Returns a list of ContentGroup objects (one per matching file), sorted
    by total number of matching lines descending so the most-relevant files
    appear first.

    If content indexing is still in progress, returns partial results from
    whatever has been indexed so far — the caller can display these and
    let the user know indexing is ongoing.

    Returns [] immediately if query is empty.
    """
    if not query.strip():
        return []

    raw_matches: list[ContentMatch] = search_content(
        state, query.strip(), max_results=max_results
    )

    # Group by file
    groups: dict[str, list[ContentMatch]] = {}
    for m in raw_matches:
        groups.setdefault(m.rel_path, []).append(m)

    result: list[ContentGroup] = []
    for rel_path, matches in groups.items():
        entry = state.file_index.get(rel_path)
        if not entry:
            continue
        # Sort matches within the file by line number
        matches.sort(key=lambda m: m.line_number)
        result.append(
            ContentGroup(
                entry=entry,
                matches=matches,
                total_lines=len(matches),
            )
        )

    # Sort groups: most matches first
    result.sort(key=lambda g: -g.total_lines)
    return result


# ── Utility ───────────────────────────────────────────────────────────────────


def content_index_status(state: IndexState) -> tuple[bool, float, str]:
    """
    Returns (is_ready, progress_fraction, human_message).
    Convenience for the UI to decide whether to show a progress banner.
    """
    if state.content_ready:
        n = len(state._content_lines)
        return True, 1.0, f"Content index ready — {n:,} files indexed."

    pct = int(state.content_progress * 100)
    n = len(state._content_lines)
    return (
        False,
        state.content_progress,
        (f"Content indexing in progress… {pct}%  ({n:,} files indexed so far)"),
    )
