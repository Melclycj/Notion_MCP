import base64
import os
import secrets
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import certifi
import httpx

NOTION_API_URL = "https://api.notion.com"
NOTION_OAUTH_AUTHORIZE_URL = f"{NOTION_API_URL}/v1/oauth/authorize"
NOTION_OAUTH_TOKEN_URL = f"{NOTION_API_URL}/v1/oauth/token"
NOTION_VERSION = "2022-06-28"
USER_AGENT = "notion-mcp/1.0"

NOTION_CLIENT_ID = os.getenv("NOTION_CLIENT_ID", "sample-client-id")
NOTION_CLIENT_SECRET = os.getenv("NOTION_CLIENT_SECRET", "sample-client-secret")
NOTION_REDIRECT_URI = os.getenv(
    "NOTION_REDIRECT_URI",
    "https://localhost:8443/oauth/notion/callback",
)
NOTION_OAUTH_OWNER = os.getenv("NOTION_OAUTH_OWNER", "user")

DEFAULT_STATE_TTL_SECONDS = 600


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _basic_auth_header(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    token = base64.b64encode(raw).decode("ascii")
    return f"Basic {token}"


@dataclass
class OAuthState:
    state: str
    created_at: datetime
    expires_at: datetime
    consumed_at: Optional[datetime] = None
    principal_id: Optional[str] = None


class InMemoryStateStore:
    """In-memory OAuth state store. Mirrors schema.sql oauth_states table."""

    def __init__(self) -> None:
        self._states: Dict[str, OAuthState] = {}

    def create(
        self,
        ttl_seconds: int = DEFAULT_STATE_TTL_SECONDS,
        principal_id: Optional[str] = None,
    ) -> OAuthState:
        state = secrets.token_urlsafe(32)
        now = _utcnow()
        expires_at = now + timedelta(seconds=ttl_seconds)
        record = OAuthState(
            state=state,
            created_at=now,
            expires_at=expires_at,
            consumed_at=None,
            principal_id=principal_id,
        )
        self._states[state] = record
        return record

    def consume(self, state: str) -> Optional[OAuthState]:
        record = self._states.get(state)
        if record is None:
            return None
        now = _utcnow()
        if record.consumed_at is not None:
            return None
        if record.expires_at <= now:
            return None
        record.consumed_at = now
        return record


@dataclass
class TokenRecord:
    access_token: str
    workspace_id: Optional[str]
    workspace_name: Optional[str]
    created_at: datetime
    scope: Optional[str]
    raw: Dict[str, Any]


class InMemoryTokenStore:
    """In-memory token store placeholder before DB persistence is added."""

    def __init__(self) -> None:
        self._last_token: Optional[TokenRecord] = None

    def save(self, record: TokenRecord) -> None:
        self._last_token = record

    def get(self) -> Optional[TokenRecord]:
        return self._last_token


STATE_STORE = InMemoryStateStore()
TOKEN_STORE = InMemoryTokenStore()


def build_authorize_url(
    state: str,
    client_id: str = NOTION_CLIENT_ID,
    redirect_uri: str = NOTION_REDIRECT_URI,
    owner: str = NOTION_OAUTH_OWNER,
) -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "owner": owner,
        "state": state,
    }
    return f"{NOTION_OAUTH_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"


def start_oauth(
    state_store: InMemoryStateStore = STATE_STORE,
    client_id: str = NOTION_CLIENT_ID,
    redirect_uri: str = NOTION_REDIRECT_URI,
    owner: str = NOTION_OAUTH_OWNER,
) -> Dict[str, str]:
    """GET /oauth/notion/start"""
    record = state_store.create()
    redirect_url = build_authorize_url(
        state=record.state,
        client_id=client_id,
        redirect_uri=redirect_uri,
        owner=owner,
    )
    return {"redirect_url": redirect_url, "state": record.state}


def exchange_token(
    code: str,
    client_id: str = NOTION_CLIENT_ID,
    client_secret: str = NOTION_CLIENT_SECRET,
    redirect_uri: str = NOTION_REDIRECT_URI,
) -> Dict[str, Any]:
    headers = {
        "Authorization": _basic_auth_header(client_id, client_secret),
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    with httpx.Client(timeout=20, verify=certifi.where()) as client:
        response = client.post(NOTION_OAUTH_TOKEN_URL, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()


def store_token(
    token_response: Dict[str, Any],
    token_store: InMemoryTokenStore = TOKEN_STORE,
) -> TokenRecord:
    record = TokenRecord(
        access_token=token_response.get("access_token", ""),
        workspace_id=token_response.get("workspace_id"),
        workspace_name=token_response.get("workspace_name"),
        created_at=_utcnow(),
        scope=token_response.get("scope"),
        raw=token_response,
    )
    token_store.save(record)
    return record


def smoke_test_search(access_token: str) -> Dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Notion-Version": NOTION_VERSION,
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    payload = {"query": "", "page_size": 1}
    with httpx.Client(timeout=20, verify=certifi.where()) as client:
        response = client.post(f"{NOTION_API_URL}/v1/search", json=payload, headers=headers)
        response.raise_for_status()
        return response.json()


def handle_callback(
    code: str,
    state: str,
    state_store: InMemoryStateStore = STATE_STORE,
    token_store: InMemoryTokenStore = TOKEN_STORE,
) -> Dict[str, Any]:
    """GET /oauth/notion/callback"""
    state_record = state_store.consume(state)
    if state_record is None:
        raise ValueError("Invalid or expired OAuth state.")

    token_response = exchange_token(code=code)
    token_record = store_token(token_response, token_store=token_store)

    smoke_test = smoke_test_search(token_record.access_token)
    return {
        "token": token_record,
        "smoke_test": smoke_test,
    }
