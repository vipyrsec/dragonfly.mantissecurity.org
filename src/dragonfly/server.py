"""API server definition"""

from contextlib import asynccontextmanager
from os import getenv

import aiohttp
import sentry_sdk
from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
# pylint: disable-next=no-name-in-module
from pydantic import BaseModel
from starlette.requests import Request

from . import __version__
from .packages import find_package_source_download_url, fetch_package_contents, search_contents
from .rules import get_rules


@asynccontextmanager
async def lifespan(app_: FastAPI):
    """Load the state for the app"""
    app_.state.rules = await get_rules()
    yield


release_prefix = getenv("DRAGONFLY_SENTRY_RELEASE_PREFIX", "dragonfly")
git_sha = getenv("GIT_SHA", "development")
sentry_sdk.init(
    dsn=getenv("DRAGONFLY_SENTRY_DSN"),
    environment=getenv("DRAGONFLY_SENTRY_ENV"),
    send_default_pii=True,
    traces_sample_rate=1.0,
    _experiments={
        "profiles_sample_rate": 1.0,
    },
    release=f"{release_prefix}@{git_sha}",
)

app = FastAPI(
    title="Dragonfly",
    description="An API to detect malware in packages uploaded to PyPI using Yara rules",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

router_root = APIRouter()


@router_root.get("/")
async def root_route():
    """Get base metadata"""
    return {
        "message": "Welcome to the API",
        "version": __version__,
    }


@router_root.post("/update-rules/")
async def update_rules(request: Request) -> bool:
    """Update the rules"""
    request.app.state.rules = await get_rules()
    return True


class PyPIPackage(BaseModel):
    """Incoming package data"""

    package_name: str


class PackageScanResults(BaseModel):
    """Results of the scan"""

    result: str
    matches: list[str]


@router_root.post("/check/")
async def pypi_check(package_metadata: PyPIPackage, request: Request) -> PackageScanResults:
    """Scan a PyPI package for malware"""
    async with aiohttp.ClientSession(raise_for_status=True) as http_session:
        if download_url := await find_package_source_download_url(
            http_session, package_metadata.package_name
        ):
            package_contents = await fetch_package_contents(
                http_session, download_url
            )
        else:
            return PackageScanResults(result="Package is a wheel.", matches=[])

        results = search_contents(request.app.state.rules, package_contents)
        if len(results) > 0:
            return PackageScanResults(result="Package is malicious!", matches=results)

        return PackageScanResults(result="Package is safe.", matches=[])


app.include_router(router_root)
