"""
OAuth 2.1 + PKCE implementation for MCP servers
"""

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
from jwt.api_jwt import decode, encode
from jwt.exceptions import PyJWTError, InvalidTokenError


@dataclass
class OAuthConfig:
    """OAuth provider configuration"""

    client_id: str
    client_secret: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str | None = None
    issuer: str = "mcp-auth"
    scopes: list[str] = None

    def __post_init__(self):
        if self.scopes is None:
            self.scopes = ["mcp:tools"]


class PKCEChallenge:
    """PKCE challenge/verifier pair"""

    def __init__(self):
        self.verifier = (
            base64.urlsafe_b64encode(secrets.token_bytes(32))
            .decode("utf-8")
            .rstrip("=")
        )

        challenge_bytes = hashlib.sha256(self.verifier.encode("utf-8")).digest()
        self.challenge = (
            base64.urlsafe_b64encode(challenge_bytes).decode("utf-8").rstrip("=")
        )


class OAuthProvider:
    """OAuth 2.1 provider with PKCE support"""

    def __init__(self, config: OAuthConfig, jwt_secret: str):
        self.config = config
        self.jwt_secret = jwt_secret
        self.sessions: dict[str, dict[str, Any]] = {}
        self.tokens: dict[str, dict[str, Any]] = {}

    def generate_authorization_url(
        self,
        redirect_uri: str,
        state: str | None = None,
        scopes: list[str] | None = None,
    ) -> tuple[str, PKCEChallenge]:
        """Generate OAuth authorization URL with PKCE"""

        pkce = PKCEChallenge()
        session_id = secrets.token_urlsafe(32)

        if state is None:
            state = secrets.token_urlsafe(16)

        if scopes is None:
            scopes = self.config.scopes

        self.sessions[session_id] = {
            "pkce_verifier": pkce.verifier,
            "state": state,
            "redirect_uri": redirect_uri,
            "scopes": scopes,
            "created_at": time.time(),
        }

        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": f"{state}:{session_id}",
            "code_challenge": pkce.challenge,
            "code_challenge_method": "S256",
        }

        auth_url = f"{self.config.authorization_endpoint}?{urlencode(params)}"
        return auth_url, pkce

    async def exchange_code_for_token(
        self, code: str, state: str, redirect_uri: str
    ) -> dict[str, Any]:
        """Exchange authorization code for access token"""

        try:
            original_state, session_id = state.split(":", 1)
        except ValueError as e:
            raise Exception from e

        session = self.sessions.get(session_id)
        if not session:
            raise ValueError("Invalid session")

        if session["state"] != original_state:
            raise ValueError("State mismatch")

        if session["redirect_uri"] != redirect_uri:
            raise ValueError("Redirect URI mismatch")

        token_data = {
            "grant_type": "authorization_code",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": session["pkce_verifier"],
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.config.token_endpoint,
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        if response.status_code != 200:
            raise ValueError(f"Token exchange failed: {response.text}")

        token_response = response.json()

        access_token = self._create_mcp_token(
            session["scopes"], token_response.get("access_token"), session_id
        )

        token_id = secrets.token_urlsafe(16)
        self.tokens[token_id] = {
            "access_token": access_token,
            "scopes": session["scopes"],
            "created_at": time.time(),
            "expires_in": 3600,
            "session_id": session_id,
        }

        del self.sessions[session_id]

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": " ".join(session["scopes"]),
        }

    def _create_mcp_token(
        self, scopes: list[str], upstream_token: str, session_id: str
    ) -> str:
        """Create MCP-scoped JWT token"""

        now = int(time.time())
        payload = {
            "iss": self.config.issuer,
            "sub": session_id,
            "aud": "mcp-server",
            "iat": now,
            "exp": now + 3600,
            "mcp_tool_scopes": scopes,
            "upstream_token": upstream_token,
        }

        return encode(payload, self.jwt_secret, algorithm="HS256")

    def introspect_token(self, token: str) -> dict[str, Any]:
        """Introspect and validate MCP token"""

        try:
            payload = decode(token, self.jwt_secret, algorithms=["HS256"])

            return {
                "active": True,
                "sub": payload.get("sub"),
                "aud": payload.get("aud"),
                "iss": payload.get("iss"),
                "exp": payload.get("exp"),
                "iat": payload.get("iat"),
                "mcp_tool_scopes": payload.get("mcp_tool_scopes", []),
                "upstream_token": payload.get("upstream_token"),
            }

        except PyJWTError:
            return {"active": False, "error": "invalid_token or token_expired"}

    def revoke_token(self, token: str) -> bool:
        """Revoke a token"""

        try:
            payload = decode(token, self.jwt_secret, algorithms=["HS256"])
            session_id = payload.get("sub")

            tokens_to_remove = [
                token_id
                for token_id, token_data in self.tokens.items()
                if token_data.get("session_id") == session_id
            ]

            for token_id in tokens_to_remove:
                del self.tokens[token_id]

            return True

        except InvalidTokenError:
            return False
