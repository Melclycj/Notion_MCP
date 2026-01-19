from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.applications import Starlette
from starlette.routing import Host
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from notion_proxy import mcp_asgi
from auth import InMemoryPrincipalStore, JWTAuthMiddleware, SupabaseJwksClient
from contextlib import asynccontextmanager
from notion_oauth import handle_callback, start_oauth

import logging
import os
from typing import Any, Dict
from dataclasses import asdict


auth_app = FastAPI()
logger = logging.getLogger("notion.oauth")
principal_store = InMemoryPrincipalStore()
jwks_client = SupabaseJwksClient()


def _serialize_token(token: Any) -> Dict[str, Any]:
    data = asdict(token)
    created_at = data.get("created_at")
    if created_at is not None:
        data["created_at"] = created_at.isoformat()
    data.pop("access_token", None)
    data.pop("raw", None)
    return data


@auth_app.get("/notion/oauth/start")
async def notion_oauth_start(_: Request) -> RedirectResponse:
    result = start_oauth()
    return RedirectResponse(result["redirect_url"], status_code=302)


@auth_app.get("/notion/oauth/callback")
async def notion_oauth_callback(request: Request) -> JSONResponse:
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code or not state:
        return JSONResponse({"error": "Missing code or state"}, status_code=400)

    try:
        result = handle_callback(code=code, state=state)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    raw = result["token"].raw
    logger.info("Notion OAuth token exchange successful.")
    logger.info("Notion access_token: %s", raw.get("access_token"))
    logger.info("Notion refresh_token: %s", raw.get("refresh_token"))

    token_payload = _serialize_token(result["token"])
    return JSONResponse(
        {
            "token": token_payload,
            "smoke_test": result["smoke_test"],
        }
    )

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp_asgi.router.lifespan_context(app):
        yield
mcp_host_app = FastAPI(lifespan=lifespan)
mcp_host_app.mount("/", mcp_asgi)

@mcp_host_app.get("/health")
def health_mcp():
    return {"ok": True, "service": "mcp"}

mcp_host_app.add_middleware(
    JWTAuthMiddleware,
    jwks_client=jwks_client,
    principal_store=principal_store,
    public_paths=["/health"],
)


# -------------------------
# Top-level host router
# -------------------------
app = Starlette(
    routes=[
        Host("auth.localhost", app=auth_app),
        Host("mcp.localhost", app=mcp_host_app),
    ]
)
#TODO, test if it is encessary
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["auth.localhost", "mcp.localhost"]
)

def get_app():
    return app
