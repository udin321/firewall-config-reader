"""
tsf/extractor.py
================
Validates and safely extracts TSF ZIP archives to isolated session directories.

Security hardening:
  - Path traversal: every member path is resolved and confirmed to stay
    inside the session root before extraction.
  - Depth limit: paths deeper than MAX_DEPTH directories are skipped.
  - Executable signatures: members whose first bytes match known PE/ELF/
    shell-script signatures are skipped.
  - Max total extracted size: aborts if cumulative bytes exceed MAX_EXTRACT_BYTES.
  - Password-protected ZIPs: detected and rejected with a clear message.
  - Symlinks inside ZIPs: any member resolving outside the session root is skipped.
"""

from __future__ import annotations

import io
import os
import shutil
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# ── Configuration ─────────────────────────────────────────────────────────────

SESSIONS_ROOT = Path("/tmp/tsf_sessions")

MAX_DEPTH = 20
MAX_EXTRACT_BYTES = 5 * 1024**3  # 5 GB total extracted size guard
MAX_ZIP_MB = 500  # maximum accepted ZIP upload in MB
MAX_SINGLE_FILE_MB = 200  # skip individual members larger than this

_SKIP_SIGS: list[bytes] = [
    b"\x4d\x5a",  # PE Windows exe/dll
    b"\x7fELF",  # ELF Linux binary
    b"#!/",  # shell shebang
    b"<?php",  # PHP
]

_SKIP_EXTS: set[str] = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".bin",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".jar",
    ".class",
    ".pyc",
}

# ── Result ────────────────────────────────────────────────────────────────────


@dataclass
class ExtractionResult:
    success: bool
    session_id: str = ""
    session_path: Path | None = None
    total_files: int = 0
    total_bytes: int = 0
    skipped: list[str] = field(default_factory=list)
    error: str = ""


# ── Public API ────────────────────────────────────────────────────────────────


def validate_and_extract(
    zip_bytes: bytes,
    progress_cb: Callable[[float, str], None] | None = None,
) -> ExtractionResult:
    """
    Validate zip_bytes as a safe TSF archive then extract to a fresh session
    directory.  progress_cb(fraction, message) is called periodically so the
    UI can update a progress bar.  fraction is in [0.0, 1.0].
    """

    def _p(frac: float, msg: str):
        if progress_cb:
            progress_cb(frac, msg)

    # Size guard
    _p(0.0, "Checking file size…")
    size_mb = len(zip_bytes) / (1024**2)
    if size_mb > MAX_ZIP_MB:
        return ExtractionResult(
            success=False,
            error=f"ZIP is {size_mb:.1f} MB — exceeds the {MAX_ZIP_MB} MB limit.",
        )

    # Open ZIP
    _p(0.05, "Validating archive structure…")
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        return ExtractionResult(
            success=False, error="The file is not a valid ZIP archive."
        )
    except Exception as exc:
        return ExtractionResult(success=False, error=f"Cannot open archive: {exc}")

    members = zf.infolist()
    if not members:
        return ExtractionResult(success=False, error="The ZIP archive is empty.")

    # Password check — probe the first readable member
    try:
        zf.read(members[0].filename)
    except RuntimeError as exc:
        if "encrypt" in str(exc).lower() or "password" in str(exc).lower():
            return ExtractionResult(
                success=False, error="Password-protected ZIP files are not supported."
            )
    except Exception:
        pass

    # Create session directory
    _p(0.10, f"Scanning {len(members):,} archive members…")
    session_id = uuid.uuid4().hex
    SESSIONS_ROOT.mkdir(parents=True, exist_ok=True)
    session_path = SESSIONS_ROOT / session_id
    session_path.mkdir(parents=True, exist_ok=True)
    session_root = session_path.resolve()

    safe_members: list[zipfile.ZipInfo] = []
    skipped: list[str] = []
    projected_size: int = 0

    for info in members:
        name = info.filename

        # Skip directory entries
        if name.endswith("/"):
            continue

        # Path traversal guard
        try:
            dest = (session_path / name).resolve()
            dest.relative_to(session_root)
        except ValueError:
            skipped.append(f"[traversal] {name}")
            continue

        # Depth limit
        if len(Path(name).parts) - 1 > MAX_DEPTH:
            skipped.append(f"[depth-exceeded] {name}")
            continue

        # Extension block
        if Path(name).suffix.lower() in _SKIP_EXTS:
            skipped.append(f"[blocked-ext] {name}")
            continue

        # Individual file size
        if info.file_size > MAX_SINGLE_FILE_MB * 1024**2:
            skipped.append(f"[file-too-large] {name}")
            continue

        # Projected total size
        projected_size += info.file_size
        if projected_size > MAX_EXTRACT_BYTES:
            skipped.append(f"[total-size-exceeded] {name}")
            continue

        safe_members.append(info)

    if not safe_members:
        shutil.rmtree(session_path, ignore_errors=True)
        return ExtractionResult(
            success=False,
            error="No extractable files found after security screening.",
            skipped=skipped,
        )

    # Extract safe members
    total = len(safe_members)
    extracted_count = 0
    extracted_bytes = 0

    for idx, info in enumerate(safe_members):
        _p(
            0.15 + 0.80 * (idx / total),
            f"Extracting {idx + 1:,}/{total:,}: {Path(info.filename).name}",
        )

        dest = session_path / info.filename
        dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            data = zf.read(info.filename)
        except RuntimeError:
            skipped.append(f"[encrypted] {info.filename}")
            continue
        except Exception as exc:
            skipped.append(f"[read-error] {info.filename}: {exc}")
            continue

        # Content signature check
        sig_sample = data[:16].lower()
        flagged = any(sig_sample.startswith(sig.lower()) for sig in _SKIP_SIGS)
        if flagged:
            skipped.append(f"[exec-sig] {info.filename}")
            continue

        try:
            dest.write_bytes(data)
            extracted_count += 1
            extracted_bytes += len(data)
        except OSError as exc:
            skipped.append(f"[write-error] {info.filename}: {exc}")

    _p(1.0, f"Done — {extracted_count:,} files extracted.")

    return ExtractionResult(
        success=True,
        session_id=session_id,
        session_path=session_path,
        total_files=extracted_count,
        total_bytes=extracted_bytes,
        skipped=skipped,
    )


def cleanup_session(session_id: str) -> None:
    """Remove a session directory and all its contents."""
    path = SESSIONS_ROOT / session_id
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def cleanup_old_sessions(max_age_hours: int = 6) -> int:
    """Delete session directories older than max_age_hours. Returns count removed."""
    import time

    removed = 0
    if not SESSIONS_ROOT.exists():
        return 0
    now = time.time()
    for child in SESSIONS_ROOT.iterdir():
        if not child.is_dir():
            continue
        if (now - child.stat().st_mtime) / 3600 > max_age_hours:
            shutil.rmtree(child, ignore_errors=True)
            removed += 1
    return removed


def get_session_path(session_id: str) -> Path | None:
    """Return the Path for a session if it still exists, else None."""
    path = SESSIONS_ROOT / session_id
    return path if path.is_dir() else None
