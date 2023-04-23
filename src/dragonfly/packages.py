"""Interactions with parsing package metadata and contents"""

import tarfile
import typing
from io import BytesIO
from typing import IO
from zipfile import ZipFile

import aiohttp

from dragonfly.models import MaliciousFile, PackageAnalysisResults

PACKAGE_SIZE_LIMIT = 2**28  # 0.25 GiB


async def fetch_package_distribution(http_session: aiohttp.ClientSession, package_source_download_url: str) -> BytesIO:
    """Fetch a package distribution from PyPI"""
    buffer = BytesIO()
    read_so_far = 0
    async with http_session.get(package_source_download_url) as response:
        async for chunk in response.content.iter_chunked(1024):
            buffer.write(chunk)
            read_so_far += len(chunk)
            if read_so_far > PACKAGE_SIZE_LIMIT:
                raise ValueError(f"Package size exceeded limit ({PACKAGE_SIZE_LIMIT} bytes)")
    buffer.seek(0)
    return buffer


def read_distribution_tarball(buffer: BytesIO) -> dict[str, str]:
    """Return a dictionary mapping filenames to content"""
    files = {}
    read_so_far = 0
    with tarfile.open(fileobj=buffer) as file:
        for tarinfo in file:
            if tarinfo.isreg():
                file_contents = []
                decompressed = typing.cast(IO[bytes], file.extractfile(tarinfo.name))
                while chunk := decompressed.read(1024):
                    file_contents.append(chunk)
                    read_so_far += len(chunk)
                    if read_so_far > PACKAGE_SIZE_LIMIT:
                        raise ValueError(f"Package size exceeded limit ({PACKAGE_SIZE_LIMIT} bytes)")
                files[tarinfo.name] = b"".join(file_contents).decode(encoding="UTF-8", errors="ignore")
    return files


def read_distribution_wheel(buffer: BytesIO) -> dict[str, str]:
    """Return a dictionary mapping filenames to content"""
    files = {}
    read_so_far = 0
    with ZipFile(file=buffer) as zip_file:
        for zip_info in zip_file.infolist():
            if not zip_info.is_dir():
                read_so_far += zip_info.file_size
                if read_so_far > PACKAGE_SIZE_LIMIT:
                    raise ValueError(f"Package size exceeded limit ({PACKAGE_SIZE_LIMIT} bytes)")
                files[zip_info.filename] = zip_file.read(zip_info).decode(encoding="UTF-8", errors="ignore")
    return files


def search_contents(rules, files: dict[str, str]) -> PackageAnalysisResults:
    """Check a directory for malicious files and return the matches"""
    malicious_files: list[MaliciousFile] = []
    for file_name, file_contents in files.items():
        if matches := rules.match(data=file_contents):
            malicious_files.append(
                MaliciousFile(
                    file_name=file_name,
                    rules={
                        match.namespace: match.meta.get("weight", 1)
                        for match in matches
                        if (filetypes := match.meta.get("filetype")) is None
                        or file_name.endswith(tuple(filetypes.split()))
                    },
                )
            )

    return PackageAnalysisResults(malicious_files=malicious_files)
