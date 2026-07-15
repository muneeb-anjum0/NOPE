from pathlib import Path
from zipfile import BadZipFile, ZipFile

from fastapi import HTTPException, UploadFile

from nope_api.config import Settings


def _is_symlink(info) -> bool:
    return (info.external_attr >> 16) & 0o170000 == 0o120000


async def extract_zip(upload: UploadFile, scan_id: str, settings: Settings) -> Path:
    content = await upload.read()
    if len(content) > settings.max_archive_bytes:
        raise HTTPException(status_code=413, detail="Archive exceeds configured maximum size.")

    workspace = settings.temp_root / scan_id
    workspace.mkdir(parents=True, exist_ok=True)
    archive_path = workspace / "upload.zip"
    archive_path.write_bytes(content)
    extracted = workspace / "repo"
    extracted.mkdir(parents=True, exist_ok=True)

    total_size = 0
    file_count = 0
    try:
        with ZipFile(archive_path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if _is_symlink(info):
                    raise HTTPException(status_code=400, detail="ZIP archives containing symlinks are not accepted.")
                file_count += 1
                total_size += info.file_size
                if file_count > settings.max_file_count:
                    raise HTTPException(status_code=413, detail="Archive contains too many files.")
                if total_size > settings.max_extracted_bytes:
                    raise HTTPException(status_code=413, detail="Extracted archive exceeds configured maximum size.")

                destination = (extracted / info.filename).resolve()
                if not str(destination).startswith(str(extracted.resolve())):
                    raise HTTPException(status_code=400, detail="ZIP archive contains path traversal.")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(info))
    except BadZipFile as exc:
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP archive.") from exc

    return extracted
