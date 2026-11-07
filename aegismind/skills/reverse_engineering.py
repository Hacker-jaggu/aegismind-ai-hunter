"""Bounded, non-executing file triage for authorized local samples."""
from __future__ import annotations
import hashlib
import re
import zipfile
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ZIP_ENTRIES = 5000
MAX_STRING_BYTES = 1024 * 1024


def identify_file(path: str | Path, *, max_bytes: int = MAX_FILE_BYTES) -> dict[str, Any]:
    """Identify common formats and extract bounded metadata; never executes the sample."""
    target = Path(path)
    if not target.is_file():
        raise FileNotFoundError(target)
    size = target.stat().st_size
    if size > max_bytes:
        raise ValueError(f"file exceeds configured size limit ({max_bytes} bytes)")
    data = target.read_bytes()
    if data.startswith(b"\x7fELF"):
        kind = "ELF"
        architecture = {3: "x86", 62: "x86_64", 40: "ARM", 183: "AArch64"}.get(
            int.from_bytes(data[18:20], "little") if len(data) >= 20 else -1, "unknown")
    elif data.startswith(b"MZ"):
        kind, architecture = "PE/DOS", "inspect PE header with a dedicated parser"
    elif data.startswith(b"PK\x03\x04"):
        kind, architecture = "ZIP container", None
    elif data.startswith(b"\xca\xfe\xba\xbe"):
        kind, architecture = "Mach-O/fat binary", "architecture table not parsed"
    elif data.startswith(b"\xfe\xed\xfa\xce") or data.startswith(b"\xfe\xed\xfa\xcf"):
        kind, architecture = "Mach-O", "header architecture not parsed"
    else:
        kind, architecture = "unknown", None
    strings = [x.decode("utf-8", "replace") for x in re.findall(rb"[\x20-\x7e]{6,}", data[:MAX_STRING_BYTES])[:200]]
    result = {
        "file_name": target.name, "size_bytes": size, "format": kind,
        "architecture": architecture, "sha256": hashlib.sha256(data).hexdigest(),
        "strings_sample": strings, "executed": False,
        "limitations": ["Static identification only; no disassembly, decompilation, signature verification, or dynamic execution.",
                        "Format/architecture detection is best-effort and does not establish safety."]
    }
    if kind == "ZIP container":
        with zipfile.ZipFile(target) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ZIP_ENTRIES:
                raise ValueError("archive contains too many entries")
            result["archive_entries"] = [
                {"name": item.filename[:240], "size": item.file_size, "compressed_size": item.compress_size}
                for item in entries[:MAX_ZIP_ENTRIES]
            ]
            result["apk_candidate"] = any(item.filename == "AndroidManifest.xml" for item in entries)
            result["limitations"].append("ZIP/APK contents are inventoried only; binary XML, DEX, signatures, and components are not decoded.")
    return result
