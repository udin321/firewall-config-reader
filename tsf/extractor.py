"""
tsf/extractor.py
================
Validates and safely extracts TSF archives (ZIP or .tgz/.tar.gz) to isolated
session directories.

Security hardening (applied identically to both archive formats):
  - Path traversal: every member path is resolved and confirmed to stay
    inside the session root before extraction.
  - Depth limit: paths deeper than MAX_DEPTH directories are skipped.
  - Executable signatures: members whose first bytes match known PE/ELF/
    shell-script signatures are skipped.
  - Max total extracted size: aborts if cumulative bytes exceed MAX_EXTRACT_BYTES.
  - Password-protected ZIPs: detected and rejected with a clear message.
  - Symlinks / hardlinks inside archives: any member resolving outside the
    session root, or any tar symlink/hardlink member, is skipped.
"""

from __future__ import annotations

import io
import os
import shutil
import tarfile
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# ── Configuration ─────────────────────────────────────────────────────────────

SESSIONS_ROOT = Path("/tmp/tsf_sessions")

MAX_DEPTH = 20
MAX_EXTRACT_BYTES = 5 * 1024**3  # 5 GB total extracted size guard
MAX_ZIP_MB = 500  # maximum accepted archive upload in MB
MAX_SINGLE_FILE_MB = 200  # skip individual members larger than this

# Magic-byte signatures used to sniff the real archive format regardless of
# the uploaded filename's extension (a mislabeled .zip that's actually a
# .tar.gz, or vice versa, is still handled correctly).
_GZIP_MAGIC = b"\x1f\x8b"
_ZIP_MAGIC = b"PK\x03\x04"

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
    archive_bytes: bytes,
    progress_cb: Callable[[float, str], None] | None = None,
) -> ExtractionResult:
    """
    Validate archive_bytes as a safe TSF archive (ZIP or .tgz/.tar.gz) then
    extract to a fresh session directory.  progress_cb(fraction, message) is
    called periodically so the UI can update a progress bar.  fraction is in
    [0.0, 1.0].

    The archive format is detected from magic bytes rather than trusting the
    uploaded filename, so a mislabeled extension can't bypass the correct
    extraction path.
    """

    def _p(frac: float, msg: str):
        if progress_cb:
            progress_cb(frac, msg)

    _p(0.0, "Checking file size…")
    size_mb = len(archive_bytes) / (1024**2)
    if size_mb > MAX_ZIP_MB:
        return ExtractionResult(
            success=False,
            error=f"Archive is {size_mb:.1f} MB — exceeds the {MAX_ZIP_MB} MB limit.",
        )

    _p(0.03, "Detecting archive format…")
    header = archive_bytes[:4]

    if header.startswith(_ZIP_MAGIC):
        return _extract_zip(archive_bytes, _p)
    if header.startswith(_GZIP_MAGIC):
        return _extract_tar(archive_bytes, _p, mode="r:gz")

    # Fall back to letting tarfile sniff uncompressed tar / other tar
    # variants (bz2, xz) — tarfile.open(mode="r:*") auto-detects compression.
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*"):
            pass
        return _extract_tar(archive_bytes, _p, mode="r:*")
    except tarfile.TarError:
        pass

    return ExtractionResult(
        success=False,
        error="Unrecognized archive format. Supported: .zip, .tgz, .tar.gz",
    )


def _new_session_dir() -> tuple[str, Path, Path]:
    """Create and return (session_id, session_path, resolved_session_root)."""
    session_id = uuid.uuid4().hex
    SESSIONS_ROOT.mkdir(parents=True, exist_ok=True)
    session_path = SESSIONS_ROOT / session_id
    session_path.mkdir(parents=True, exist_ok=True)
    return session_id, session_path, session_path.resolve()


def _extract_zip(
    zip_bytes: bytes,
    _p: Callable[[float, str], None],
) -> ExtractionResult:
    """ZIP extraction path — unchanged from the original implementation."""
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

    _p(0.10, f"Scanning {len(members):,} archive members…")
    session_id, session_path, session_root = _new_session_dir()

    safe_members: list[zipfile.ZipInfo] = []
    skipped: list[str] = []
    projected_size: int = 0

    for info in members:
        name = info.filename

        if name.endswith("/"):
            continue

        try:
            dest = (session_path / name).resolve()
            dest.relative_to(session_root)
        except ValueError:
            skipped.append(f"[traversal] {name}")
            continue

        if len(Path(name).parts) - 1 > MAX_DEPTH:
            skipped.append(f"[depth-exceeded] {name}")
            continue

        if Path(name).suffix.lower() in _SKIP_EXTS:
            skipped.append(f"[blocked-ext] {name}")
            continue

        if info.file_size > MAX_SINGLE_FILE_MB * 1024**2:
            skipped.append(f"[file-too-large] {name}")
            continue

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

        sig_sample = data[:16].lower()
        if any(sig_sample.startswith(sig.lower()) for sig in _SKIP_SIGS):
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


def _extract_tar(
    tar_bytes: bytes,
    _p: Callable[[float, str], None],
    mode: str = "r:gz",
) -> ExtractionResult:
    """
    .tgz / .tar.gz extraction path, applying the same security checks as
    _extract_zip: path traversal, depth limit, blocked extensions, per-file
    and total size limits, and executable-signature screening. Additionally
    rejects symlink and hardlink members outright, since tar (unlike zip)
    can encode links that point anywhere on the filesystem.
    """
    _p(0.05, "Validating archive structure…")
    try:
        tf = tarfile.open(fileobj=io.BytesIO(tar_bytes), mode=mode)
    except tarfile.ReadError:
        return ExtractionResult(
            success=False, error="The file is not a valid .tgz/.tar.gz archive."
        )
    except Exception as exc:
        return ExtractionResult(success=False, error=f"Cannot open archive: {exc}")

    try:
        members = tf.getmembers()
    except Exception as exc:
        return ExtractionResult(
            success=False, error=f"Cannot read archive members: {exc}"
        )

    if not members:
        return ExtractionResult(success=False, error="The archive is empty.")

    _p(0.10, f"Scanning {len(members):,} archive members…")
    session_id, session_path, session_root = _new_session_dir()

    safe_members: list[tarfile.TarInfo] = []
    skipped: list[str] = []
    projected_size: int = 0

    for info in members:
        name = info.name

        if info.isdir():
            continue

        # Reject links outright — tar links can point anywhere on the
        # filesystem and cannot be validated the same way a plain path can.
        if info.issym() or info.islnk():
            skipped.append(f"[link-rejected] {name}")
            continue

        if not info.isfile():
            skipped.append(f"[non-regular-file] {name}")
            continue

        try:
            dest = (session_path / name).resolve()
            dest.relative_to(session_root)
        except ValueError:
            skipped.append(f"[traversal] {name}")
            continue

        if len(Path(name).parts) - 1 > MAX_DEPTH:
            skipped.append(f"[depth-exceeded] {name}")
            continue

        if Path(name).suffix.lower() in _SKIP_EXTS:
            skipped.append(f"[blocked-ext] {name}")
            continue

        if info.size > MAX_SINGLE_FILE_MB * 1024**2:
            skipped.append(f"[file-too-large] {name}")
            continue

        projected_size += info.size
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

    total = len(safe_members)
    extracted_count = 0
    extracted_bytes = 0

    for idx, info in enumerate(safe_members):
        _p(
            0.15 + 0.80 * (idx / total),
            f"Extracting {idx + 1:,}/{total:,}: {Path(info.name).name}",
        )

        dest = session_path / info.name
        dest.parent.mkdir(parents=True, exist_ok=True)

        try:
            extracted = tf.extractfile(info)
            if extracted is None:
                skipped.append(f"[unreadable] {info.name}")
                continue
            data = extracted.read()
        except Exception as exc:
            skipped.append(f"[read-error] {info.name}: {exc}")
            continue

        sig_sample = data[:16].lower()
        if any(sig_sample.startswith(sig.lower()) for sig in _SKIP_SIGS):
            skipped.append(f"[exec-sig] {info.name}")
            continue

        try:
            dest.write_bytes(data)
            extracted_count += 1
            extracted_bytes += len(data)
        except OSError as exc:
            skipped.append(f"[write-error] {info.name}: {exc}")

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
