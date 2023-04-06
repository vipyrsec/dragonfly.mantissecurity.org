"""Interactions with Yara rules"""

from io import BytesIO
from os import getenv
from typing import Final
from zipfile import ZipFile

import aiohttp
import yara

REPO_ZIP_URL: Final[str] = "https://api.github.com/repos/SkeletalDemise/DragonFly/zipball/"
REPO_TOP_COMMIT_URL: Final[str] = "https://api.github.com/repos/SkeletalDemise/DragonFly/commits/main"
AUTH_HEADERS: Final[dict[str, str]] = {"Authorization": f"Bearer {getenv('DRAGONFLY_GITHUB_TOKEN')}"}
JSON_HEADERS: Final[dict[str, str]] = {"Accept": "application/vnd.github.VERSION.sha"}


async def _fetch_rules() -> tuple[str, dict[str, str]]:
    """Return a dictionary mapping filenames to content"""
    files = {}
    buffer = BytesIO()
    async with aiohttp.ClientSession(raise_for_status=True, headers=AUTH_HEADERS) as http_session:
        async with http_session.get(REPO_ZIP_URL) as response:
            buffer.write(await response.content.read())
        async with http_session.get(REPO_TOP_COMMIT_URL, headers=JSON_HEADERS) as response:
            data = await response.read()
            rules_commit = data.decode()
    buffer.seek(0)
    with ZipFile(buffer) as zip_file:
        for file_path in zip_file.namelist():
            if file_path.endswith(".yara"):
                file_name = file_path.split("/")[-1]
                file_name = file_name.removesuffix(".yara")
                files[file_name] = zip_file.read(file_path).decode()
    return rules_commit, files


async def get_rules() -> tuple[str, yara.Rules]:
    """Fetch and compile the rules"""
    rules_commit, sources = await _fetch_rules()
    return rules_commit, yara.compile(sources=sources)
