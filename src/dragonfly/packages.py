"""Interactions with parsing package metadata and contents"""

import tarfile
from dataclasses import dataclass
from io import BytesIO

import aiohttp


@dataclass
class MaliciousFile:
    """Represents a malicious file, which YARA rules it matched, and it's individual score"""

    filename: str
    """Filename"""

    rules: list[str]
    """Rules that this file matched"""

    score: int
    """Individual score for this file only"""


@dataclass
class PackageAnalysisResults:
    """Results of analysing a PyPi package for malware"""

    malicious_files: list[MaliciousFile]

    def calculate_total_score(self) -> int:
        return sum(file.score for file in self.malicious_files)


async def find_package_source_download_url(http_session: aiohttp.ClientSession, package_title: str) -> str | None:
    """Find the `.tar.gz` download for a package.
    Return `None` if there are no files or if only wheels are available."""
    metadata_url = f"https://pypi.org/pypi/{package_title}/json"
    async with http_session.get(metadata_url) as response:
        package_metadata = await response.json()

    if "urls" not in package_metadata:
        return None

    for url in package_metadata["urls"]:
        if url["url"].endswith(".tar.gz"):
            return url["url"]

    return None


async def fetch_package_contents(
    http_session: aiohttp.ClientSession, package_source_download_url: str
) -> dict[str, str]:
    """Return a dictionary mapping filenames to content"""
    files = {}
    buffer = BytesIO()
    async with http_session.get(package_source_download_url) as response:
        buffer.write(await response.content.read())
    buffer.seek(0)
    with tarfile.open(fileobj=buffer) as file:
        for tarinfo in file:
            if tarinfo.isreg():
                files[tarinfo.name] = file.extractfile(tarinfo.name).read().decode(encoding="UTF-8", errors="ignore")
    return files


def search_contents(rules, files: dict[str, str]) -> PackageAnalysisResults:
    """Check a directory for malicious files and return the matches"""
    malicious_files: list[MaliciousFile] = []
    for file_name, file_contents in files.items():
        matches = rules.match(data=file_contents)
        file = MaliciousFile(
            filename=file_name,
            rules=[match.namespace for match in matches],
            score=sum(match.meta.get("weight", 1) for match in matches),
        )
        malicious_files.append(file)

    return PackageAnalysisResults(malicious_files=malicious_files)
