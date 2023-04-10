"""API server definition"""

from contextlib import asynccontextmanager
from os import getenv

import aiohttp
import sentry_sdk
from aiohttp import ClientResponseError
from fastapi import APIRouter, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

# pylint: disable-next=no-name-in-module
from pydantic import BaseModel
from starlette.requests import Request

from . import __version__
from .packages import (
    MaliciousFile,
    fetch_package_contents,
    find_package_source_download_url,
    get_package,
    search_contents,
)
from .rules import get_rules


@asynccontextmanager
async def lifespan(app_: FastAPI):
    """Load the state for the app"""
    rules_commit, rules = await get_rules()
    app_.state.rules_commit = rules_commit
    app_.state.rules = rules
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


class Error(BaseModel):
    """Returned when an error occurs"""

    detail: str


router_root = APIRouter()


class ServerMetadata(BaseModel):
    """Metadata about the server"""

    version: str
    server_commit: str
    rules_commit: str


@router_root.get("/")
async def root_route(request: Request) -> ServerMetadata:
    """Get server metadata"""
    try:
        rules_commit = request.app.state.rules_commit
    except AttributeError:
        rules_commit = "inside_ci"
    return ServerMetadata(
        version=__version__,
        server_commit=getenv("GIT_SHA", "development"),
        rules_commit=rules_commit,
    )


@router_root.post("/update-rules/")
async def update_rules(request: Request) -> str:
    """Update the rules"""
    rules_commit, rules = await get_rules()
    request.app.state.rules_commit = rules_commit
    request.app.state.rules = rules
    return True


class PyPIPackage(BaseModel):
    """Incoming package data"""

    package_name: str


class PackageScanResults(BaseModel):
    """Results of the scan"""

    # File with the highest score
    most_malicious_file: str

    # All unique yara rules that were matched. Note that this is across the entire package.
    matches: list[str]

    # Pypi link to the package itself
    pypi_link: str

    # Inspector link to the offending file
    inspector_link: str

    # Total score of the entire package
    score: int


@router_root.post("/check/", responses={404: {"model": Error, "description": "The package was not found"}})
async def pypi_check(package_metadata: PyPIPackage, request: Request) -> PackageScanResults:
    """Scan a PyPI package for malware"""
    try:
        async with aiohttp.ClientSession(raise_for_status=True) as http_session:
            package = await get_package(http_session, package_metadata.package_name)
            if download_url := package.download_url:
                package_contents = await fetch_package_contents(http_session, download_url)
            else:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Package is a wheel!",
                )

            analysis = search_contents(request.app.state.rules, package_contents)
            most_malicious_file = max(analysis.malicious_files, key=MaliciousFile.calculate_file_score).filename
            return PackageScanResults(
                most_malicious_file=most_malicious_file,
                matches=list(analysis.get_matched_rules().keys()),
                pypi_link=package.pypi_url,
                inspector_link=f"{package.inspector_url}/{most_malicious_file}",
                score=analysis.calculate_package_score(),
            )

    except ClientResponseError as exception:
        raise HTTPException(
            status_code=exception.status,
            detail=f"Upstream responded with '{exception.message}'!",
        )


app.include_router(router_root)
