"""API server definition"""

import logging
import sys
from contextlib import asynccontextmanager
from os import getenv

import aiohttp
import sentry_sdk
from aiohttp import ClientResponseError
from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from letsbuilda.pypi import PyPIServices
from starlette.requests import Request

from . import __version__
from .constants import HEADERS
from .models import (
    Error,
    HighestScoreDistribution,
    MaliciousFile,
    PackageDistributionScanResults,
    PackageScanResults,
    PyPIPackage,
    ServerMetadata,
)
from .packages import (
    fetch_package_distribution,
    read_distribution_tarball,
    read_distribution_wheel,
    search_contents,
)
from .rules import get_rules

logger = logging.getLogger(__file__)
logger.addHandler(logging.StreamHandler(sys.stderr))


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
    traces_sample_rate=0.0025,
    profiles_sample_rate=0.0025,
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


@router_root.post(
    "/check/",
    responses={
        404: {"model": Error, "description": "The package was not found"},
        507: {"model": Error, "description": "The package was too large to proceed"},
    },
)
async def pypi_check(incoming_metadata: PyPIPackage, request: Request) -> PackageScanResults:
    """Scan a PyPI package for malware"""
    try:
        async with aiohttp.ClientSession(raise_for_status=True, headers=HEADERS) as http_session:
            pypi_client = PyPIServices(http_session)
            package_metadata = await pypi_client.get_package_metadata(
                incoming_metadata.package_name,
                incoming_metadata.package_version,
            )

            distribution_scan_results: list[PackageDistributionScanResults] = []
            for url in package_metadata.urls:
                try:
                    distribution_bytes = await fetch_package_distribution(http_session, url.url)
                    if url.packagetype == "sdist":
                        package_contents = read_distribution_tarball(distribution_bytes)
                    else:
                        package_contents = read_distribution_wheel(distribution_bytes)
                except ValueError:
                    logger.error("Package '%s' was too large to scan!")
                    raise HTTPException(
                        status_code=507,
                        detail="Package '%s' was too large to scan!",
                    ) from None

                distribution_scan_results.append(
                    PackageDistributionScanResults(
                        file_name=url.filename,
                        inspector_url=url.inspector_url,
                        analysis=search_contents(request.app.state.rules, package_contents),
                    )
                )

            highest_scoring_distribution = max(
                distribution_scan_results, key=lambda result: result.analysis.calculate_package_score()
            )
            highest_score = highest_scoring_distribution.analysis.calculate_package_score()
            if highest_score > 0:
                most_malicious_file = max(
                    highest_scoring_distribution.analysis.malicious_files, key=MaliciousFile.calculate_file_score
                ).file_name

                highest_score_distribution = HighestScoreDistribution(
                    score=highest_score,
                    matches=list(highest_scoring_distribution.analysis.get_matched_rules().keys()),
                    most_malicious_file=most_malicious_file,
                    inspector_link=f"{highest_scoring_distribution.inspector_url}/{most_malicious_file}",
                )
            else:
                highest_score_distribution = None

            return PackageScanResults(
                name=package_metadata.info.name,
                version=package_metadata.info.version,
                pypi_link=package_metadata.info.package_url,
                distributions=distribution_scan_results,
                highest_score_distribution=highest_score_distribution,
            )

    except ClientResponseError as exception:
        raise HTTPException(
            status_code=exception.status,
            detail=f"Upstream responded with '{exception.message}'!",
        )


app.include_router(router_root)
