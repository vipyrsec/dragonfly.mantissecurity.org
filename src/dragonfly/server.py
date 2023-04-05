"""API server definition"""

from os import getenv

import sentry_sdk
from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import __version__

release_prefix = getenv("API_SENTRY_RELEASE_PREFIX", "dragonfly")
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


app.include_router(router_root)
