"""API server definition"""

import argparse
import logging
import sys
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
from .decorators import debug_func
from .packages import (
    MaliciousFile,
    fetch_package_contents,
    get_package,
    search_contents,
)
from .rules import get_rules

parser = argparse.ArgumentParser()
parser.add_argument("--debug", action="store_true", default=False)
args = parser.parse_args()

debug = args.debug

logger = logging.getLogger(__file__)
logger.addHandler(logging.StreamHandler(sys.stderr))

logger.setLevel(logging.DEBUG if debug else logging.WARNING)


@debug_func
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
    profiles_sample_rate=1.0,
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


@debug_func
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


@debug_func
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

    # Package name
    name: str

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

    # Version of the package that was checked
    version: str


@debug_func
@router_root.post(
    "/check/",
    responses={
        404: {"model": Error, "description": "The package was not found"},
        507: {"model": Error, "description": "The package was too large to proceed"},
    },
)
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

            try:
                analysis = search_contents(request.app.state.rules, package_contents)
            except ValueError:
                logger.error("Package '%s' was too large to scan!")
                raise HTTPException(
                    status_code=507,
                    detail="Package '%s' was too large to scan!",
                ) from None

            most_malicious_file = max(analysis.malicious_files, key=MaliciousFile.calculate_file_score).filename
            return PackageScanResults(
                name=package.name,
                most_malicious_file=most_malicious_file,
                matches=list(analysis.get_matched_rules().keys()),
                pypi_link=package.pypi_url,
                inspector_link=f"{package.inspector_url}/{most_malicious_file}",
                score=analysis.calculate_package_score(),
                version=package.version,
            )

    except ClientResponseError as exception:
        logger.warning(f"Upstream responded with '{exception.message}'!")
        raise HTTPException(
            status_code=exception.status,
            detail=f"Upstream responded with '{exception.message}'!",
        )


app.include_router(router_root)
