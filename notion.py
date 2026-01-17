from __future__ import annotations

from dataclasses import asdict
import logging
from typing import Any, Dict

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

from notion_oauth import handle_callback, start_oauth

# Initialize FastMCP server
mcp = FastMCP("notion")
logger = logging.getLogger("notion.oauth")


def _serialize_token(token: Any) -> Dict[str, Any]:
    data = asdict(token)
    created_at = data.get("created_at")
    if created_at is not None:
        data["created_at"] = created_at.isoformat()
    data.pop("access_token", None)
    data.pop("raw", None)
    return data


@mcp.custom_route("/oauth/notion/start", methods=["GET"])
async def notion_oauth_start(_: Request) -> RedirectResponse:
    result = start_oauth()
    return RedirectResponse(result["redirect_url"], status_code=302)


@mcp.custom_route("/oauth/notion/callback", methods=["GET"])
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


def get_app():
    return mcp.streamable_http_app()
