"""Interactions with Yara rules"""

from io import BytesIO
from os import getenv
from typing import Final
from zipfile import ZipFile

import aiohttp
import yara

REPO_ZIP_URL: Final[str] = "https://api.github.com/repos/SkeletalDemise/DragonFly/zipball/"
HEADERS: Final[dict[str, str]] = {"Authorization": f"Bearer {getenv('DRAGONFLY_GITHUB_TOKEN')}"}


async def _fetch_rules() -> dict[str, str]:
    """Return a dictionary mapping filenames to content"""
    files = {}
    buffer = BytesIO()
    async with aiohttp.ClientSession(raise_for_status=True, headers=HEADERS) as http_session:
        async with http_session.get(REPO_ZIP_URL) as response:
            buffer.write(await response.content.read())
    buffer.seek(0)
    with ZipFile(buffer) as zip_file:
        for file_name in zip_file.namelist():
            if file_name.endswith(".yara"):
                files[file_name.removesuffix(".yara")] = zip_file.read(file_name).decode()
    return files


async def get_rules() -> "compiled yara rules":
    """Fetch and compile the rules"""
    sources = await _fetch_rules()
    return yara.compile(sources=sources)
