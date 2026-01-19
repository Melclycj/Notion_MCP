from __future__ import annotations
from typing import Any, Dict

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from auth import InMemoryPrincipalStore, JWTAuthMiddleware, SupabaseJwksClient

import os

# Initialize FastMCP server
mcp = FastMCP("notion")

@mcp.tool()
def ping() -> str:
    return "pong"

AUTH_URL = os.getenv("AUTH_URL", "https://auth.localhost:8443")

"""-- METADATA --"""
@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def get_oauth_protected_resource_metadata(_: Request) -> JSONResponse:
    metadata = {
        "resource": f"{AUTH_URL}",
        "authorization_servers": [f"{AUTH_URL}"],
        "scopes_supported": ["mcp:read", "mcp:write"]
    }
    return JSONResponse(metadata)


# Creates an ASGI app that serves MCP over HTTP.
mcp_asgi = mcp.streamable_http_app()

