"""
MCP server middleware for OAuth authentication and authorization
"""

import functools
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from mcp.server import FastMCP

from .oauth import OAuthProvider
from .policy import PolicyEngine


@dataclass
class AuthContext:
    """Authentication context passed to MCP tools"""

    user_id: str
    scopes: list[str]
    claims: dict[str, Any]
    token: str


class MCPAuthMiddleware:
    """Authentication middleware for MCP servers"""

    def __init__(self, oauth_provider: OAuthProvider, policy_engine: PolicyEngine):
        self.oauth_provider = oauth_provider
        self.policy_engine = policy_engine

    def authenticate_request(self, authorization_header: str) -> AuthContext | None:
        """Extract and validate auth token from request"""

        if not authorization_header:
            return None

        if not authorization_header.startswith("Bearer "):
            return None

        token = authorization_header[7:]  # Remove 'Bearer ' prefix

        token_info = self.oauth_provider.introspect_token(token)

        if not token_info.get("active"):
            return None

        return AuthContext(
            user_id=token_info.get("sub", "unknown"),
            scopes=token_info.get("mcp_tool_scopes", []),
            claims=token_info,
            token=token,
        )

    def authorize_tool_call(
        self, tool_name: str, auth_context: AuthContext
    ) -> tuple[bool, str | None]:
        """Check if user can call the specified tool"""

        return self.policy_engine.authorize_tool_call(
            tool_name=tool_name,
            user_scopes=auth_context.scopes,
            user_claims=auth_context.claims,
        )


def auth_required(
    oauth_provider: OAuthProvider,
    policy_engine: PolicyEngine,
    tool_name: str | None = None,
):
    """
    Decorator to require authentication for MCP tool functions

    Usage:
        @auth_required(oauth_provider, policy_engine, "read_files")
        def my_tool_function(context: AuthContext, ...):
            pass
    """

    def decorator(func: Callable) -> Callable:
        middleware = MCPAuthMiddleware(oauth_provider, policy_engine)

        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            auth_header = kwargs.pop("authorization", None)

            if not auth_header:
                raise PermissionError("Authorization header required")

            auth_context = middleware.authenticate_request(auth_header)

            if not auth_context:
                raise PermissionError("Invalid or expired token")

            actual_tool_name = tool_name or func.__name__

            authorized, reason = middleware.authorize_tool_call(
                actual_tool_name, auth_context
            )

            if not authorized:
                raise PermissionError(f"Access denied: {reason}")

            return await func(auth_context, *args, **kwargs)

        return wrapper

    return decorator


class FastMCPAuthWrapper:
    """Wrapper for FastMCP servers to add authentication"""

    def __init__(
        self,
        mcp_server: FastMCP,
        oauth_provider: OAuthProvider,
        policy_engine: PolicyEngine,
    ):
        self.mcp_server = mcp_server
        self.middleware = MCPAuthMiddleware(oauth_provider, policy_engine)
        self._wrap_tools()

    def _wrap_tools(self):
        """Wrap all existing tools with auth middleware"""

        if hasattr(self.mcp_server._tool_manager, "_tools"):
            original_tools = self.mcp_server._tool_manager._tools.copy()

            for tool_name, tool_func in original_tools.items():
                wrapped_func = self._create_auth_wrapper(tool_name, tool_func)
                self.mcp_server._tool_manager._tools[tool_name] = wrapped_func

    def _create_auth_wrapper(self, tool_name: str, original_func: Callable) -> Callable:
        """Create auth wrapper for a specific tool"""

        @functools.wraps(original_func)
        async def auth_wrapper(*args, **kwargs):
            auth_header = kwargs.pop("authorization", None)

            if not auth_header:
                raise PermissionError("Authorization required")

            auth_context = self.middleware.authenticate_request(auth_header)

            if not auth_context:
                raise PermissionError("Invalid token")

            authorized, reason = self.middleware.authorize_tool_call(
                tool_name, auth_context
            )

            if not authorized:
                raise PermissionError(f"Access denied: {reason}")

            kwargs["auth_context"] = auth_context
            return await original_func(*args, **kwargs)

        return auth_wrapper

    def add_auth_endpoints(self):
        """Add OAuth endpoints to the MCP server"""

        @self.mcp_server.resource("oauth://authorize?redirect_uri={redirect_uri}&scopes={scopes}")
        async def oauth_authorize(redirect_uri: str, scopes: str | None = None):
            """OAuth authorization endpoint"""
            scope_list = scopes.split(" ") if scopes else None
            auth_url, pkce = self.middleware.oauth_provider.generate_authorization_url(
                redirect_uri=redirect_uri, scopes=scope_list
            )
            return {
                "authorization_url": auth_url,
                "code_verifier": pkce.verifier,  # For PKCE flow
            }

        @self.mcp_server.tool()
        async def oauth_token(
            code: str,
            state: str,
            redirect_uri: str,
            auth_context: AuthContext | None = None,
        ):
            """OAuth token exchange endpoint"""
            return await self.middleware.oauth_provider.exchange_code_for_token(
                code=code, state=state, redirect_uri=redirect_uri
            )

        @self.mcp_server.tool()
        async def oauth_introspect(
            token: str, auth_context: AuthContext | None = None
        ):
            """Token introspection endpoint"""
            return self.middleware.oauth_provider.introspect_token(token)

        @self.mcp_server.tool()
        async def oauth_revoke(token: str, auth_context: AuthContext | None = None):
            """Token revocation endpoint"""
            success = self.middleware.oauth_provider.revoke_token(token)
            return {"revoked": success}
