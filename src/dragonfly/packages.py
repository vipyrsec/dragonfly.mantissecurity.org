"""Interactions with parsing package metadata and contents"""

import tarfile
from dataclasses import dataclass
from io import BytesIO
from urllib.parse import urlparse, urlunparse

import aiohttp


@dataclass
class Package:
    """Dataclass representing a PyPi package with a few interesting properties included"""

    author: str
    author_email: str | None
    description: str | None
    name: str
    pypi_url: str
    version: str
    inspector_url: str
    download_url: str | None


@dataclass
class MaliciousFile:
    """Represents a malicious file, which YARA rules it matched, and it's individual score"""

    # Filename
    filename: str

    # Mapping of rule name to rule score
    rules: dict[str, int]

    def calculate_file_score(self) -> int:
        return sum(self.rules.values())


@dataclass
class PackageAnalysisResults:
    """Results of analysing a PyPi package for malware"""

    malicious_files: list[MaliciousFile]

    def get_matched_rules(self) -> dict[str, int]:
        """Aggregate all of the matches rules and return the rule name mapped to it's weight"""
        rules: dict[str, int] = {}
        for file in self.malicious_files:
            for rule, weight in file.rules.items():
                rules[rule] = weight

        return rules

    def calculate_package_score(self) -> int:
        return sum(self.get_matched_rules().values())


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


async def get_package(http_session: aiohttp.ClientSession, package_title: str) -> Package:
    """Find the inspector URL pointing to the root of the latest version of the package"""
    metadata_url = f"https://pypi.org/pypi/{package_title}/json"
    async with http_session.get(metadata_url) as response:
        package_metadata = await response.json()
        info = package_metadata["info"]

    version = info["version"]
    download_url = await find_package_source_download_url(http_session, package_title)
    inspector_url = urlparse(download_url)
    inspector_url = inspector_url._replace(netloc="inspector.pypi.io")._replace(
        path=f"project/{package_title}/{version}" + str(inspector_url.path)
    )
    inspector_url = str(urlunparse(inspector_url))

    return Package(
        author=info["author"],
        author_email=info.get("author_email"),
        description=info["description"] or None,
        name=info["name"],
        pypi_url=info["package_url"],
        version=version,
        inspector_url=inspector_url,
        download_url=download_url,
    )


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
            rules={match.namespace: match.meta.get("weight", 1) for match in matches},
        )
        malicious_files.append(file)

    return PackageAnalysisResults(malicious_files=malicious_files)
