from pathlib import Path
import shutil
import stat
import unicodedata
from zipfile import BadZipFile, ZipFile

from fastapi import HTTPException, UploadFile

from nope_api.config import Settings


def _is_symlink(info) -> bool:
    return (info.external_attr >> 16) & 0o170000 == 0o120000


def _file_type(info) -> int:
    return (info.external_attr >> 16) & 0o170000


def _is_special_file(info) -> bool:
    mode = _file_type(info)
    return mode not in {0, stat.S_IFREG, stat.S_IFDIR} and mode != 0o100000


def _safe_member_path(filename: str, settings: Settings) -> Path:
    normalized = unicodedata.normalize("NFC", filename.replace("\\", "/"))
    if "\x00" in normalized:
        raise HTTPException(status_code=400, detail="ZIP archive contains an invalid path.")
    parts = [part for part in Path(normalized).parts if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts) or Path(normalized).is_absolute():
        raise HTTPException(status_code=400, detail="ZIP archive contains path traversal.")
    if len(normalized) > settings.max_archive_path_length:
        raise HTTPException(status_code=413, detail="ZIP archive contains an excessively long path.")
    if len(parts) > settings.max_archive_nesting_depth:
        raise HTTPException(status_code=413, detail="ZIP archive nesting is too deep.")
    return Path(*parts)


async def extract_zip(upload: UploadFile, scan_id: str, settings: Settings) -> Path:
    content = await upload.read()
    if len(content) > settings.max_archive_bytes:
        raise HTTPException(status_code=413, detail="Archive exceeds configured maximum size.")

    workspace = settings.temp_root / scan_id
    if workspace.exists():
        shutil.rmtree(workspace, ignore_errors=True)
    workspace.mkdir(parents=True, exist_ok=True)
    archive_path = workspace / "upload.zip"
    archive_path.write_bytes(content)
    extracted = workspace / "repo"
    extracted.mkdir(parents=True, exist_ok=True)

    total_size = 0
    file_count = 0
    seen_paths: set[str] = set()
    try:
        with ZipFile(archive_path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if _is_symlink(info):
                    raise HTTPException(status_code=400, detail="ZIP archives containing symlinks are not accepted.")
                if _is_special_file(info):
                    raise HTTPException(status_code=400, detail="ZIP archives containing hardlinks or special files are not accepted.")
                if info.compress_size and info.file_size / max(info.compress_size, 1) > settings.max_archive_compression_ratio:
                    raise HTTPException(status_code=413, detail="ZIP archive compression ratio is too high.")
                file_count += 1
                total_size += info.file_size
                if file_count > settings.max_file_count:
                    raise HTTPException(status_code=413, detail="Archive contains too many files.")
                if total_size > settings.max_extracted_bytes:
                    raise HTTPException(status_code=413, detail="Extracted archive exceeds configured maximum size.")

                member_path = _safe_member_path(info.filename, settings)
                normalized_key = member_path.as_posix().casefold()
                if normalized_key in seen_paths:
                    raise HTTPException(status_code=400, detail="ZIP archive contains duplicate paths.")
                seen_paths.add(normalized_key)
                destination = (extracted / member_path).resolve()
                if not str(destination).startswith(str(extracted.resolve())):
                    raise HTTPException(status_code=400, detail="ZIP archive contains path traversal.")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(info))
    except BadZipFile as exc:
        shutil.rmtree(workspace, ignore_errors=True)
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP archive.") from exc
    except HTTPException:
        shutil.rmtree(workspace, ignore_errors=True)
        raise

    return extracted
