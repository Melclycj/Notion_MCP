from __future__ import annotations

import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

import httpx
import jwt
from dotenv import load_dotenv
from jwt import algorithms
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

load_dotenv()

SUPABASE_PROJECT_URL = os.getenv("SUPABASE_PROJECT_URL", "https://your-project.supabase.co")
SUPABASE_JWT_AUDIENCE = os.getenv("SUPABASE_JWT_AUDIENCE", "authenticated")
SUPABASE_ISSUER = os.getenv("SUPABASE_ISSUER_URL") or f"{SUPABASE_PROJECT_URL}/auth/v1"
SUPABASE_JWKS_URL = os.getenv("SUPABASE_JWKS_URL") or f"{SUPABASE_ISSUER}/.well-known/jwks.json"

DEFAULT_JWKS_TTL_SECONDS = 3600


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class PrincipalRecord:
    iss: str
    sub: str
    created_at: datetime


class InMemoryPrincipalStore:
    """In-memory principal store placeholder before DB persistence is added."""

    def __init__(self) -> None:
        self._records: Dict[str, PrincipalRecord] = {}

    def get_or_create(self, iss: str, sub: str) -> PrincipalRecord:
        key = f"{iss}|{sub}"
        record = self._records.get(key)
        if record is None:
            record = PrincipalRecord(iss=iss, sub=sub, created_at=_utcnow())
            self._records[key] = record
        return record


class SupabaseJwksClient:
    def __init__(self, jwks_url: str = SUPABASE_JWKS_URL, ttl_seconds: int = DEFAULT_JWKS_TTL_SECONDS) -> None:
        self._jwks_url = jwks_url
        self._ttl_seconds = ttl_seconds
        self._jwks: Optional[Dict[str, Any]] = None
        self._fetched_at: Optional[float] = None

    def get_jwks(self) -> Dict[str, Any] | None:
        now = time.time()
        if self._jwks and self._fetched_at and (now - self._fetched_at) < self._ttl_seconds:
            return self._jwks
        with httpx.Client(timeout=10) as client:
            response = client.get(self._jwks_url)
            response.raise_for_status()
            self._jwks = response.json()
            self._fetched_at = now
            return self._jwks

    def get_key(self, kid: str) -> Any:
        jwks = self.get_jwks()
        if not jwks:
            raise ValueError("No JWKS available.")
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return algorithms.RSAAlgorithm.from_jwk(key)
        raise ValueError("No matching JWKS key found.")


def verify_jwt(
    token: str,
    jwks_client: SupabaseJwksClient,
    audience: str = SUPABASE_JWT_AUDIENCE,
    issuer: str = SUPABASE_ISSUER,
) -> Dict[str, Any]:
    headers = jwt.get_unverified_header(token)
    kid = headers.get("kid")
    if not kid:
        raise ValueError("JWT missing kid header.")
    key = jwks_client.get_key(kid)
    return jwt.decode(
        token,
        key=key,
        algorithms=["RS256"],
        audience=audience,
        issuer=issuer,
    )


def _is_public_path(path: str, public_paths: Iterable[str]) -> bool:
    return any(path.startswith(public_path) for public_path in public_paths)


class JWTAuthMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        jwks_client: SupabaseJwksClient,
        principal_store: InMemoryPrincipalStore,
        public_paths: Iterable[str],
    ) -> None:
        super().__init__(app)
        self._jwks_client = jwks_client
        self._principal_store = principal_store
        self._public_paths = list(public_paths)

    async def dispatch(self, request: Request, call_next):
        if _is_public_path(request.url.path, self._public_paths):
            return await call_next(request)

        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse({"error": "Missing Bearer token."}, status_code=401)

        token = auth_header.split(" ", 1)[1]
        try:
            payload = verify_jwt(token, self._jwks_client)
        except Exception as exc:
            return JSONResponse({"error": f"Invalid token: {exc}"}, status_code=401)

        iss = payload.get("iss", "")
        sub = payload.get("sub", "")
        if not iss or not sub:
            return JSONResponse({"error": "Token missing iss/sub."}, status_code=401)

        request.state.principal = self._principal_store.get_or_create(iss=iss, sub=sub)
        request.state.jwt_payload = payload
        return await call_next(request)
