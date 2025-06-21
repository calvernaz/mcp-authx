"""
MCP Auth Toolkit - OAuth 2.1 + Authorization for Model Context Protocol Servers
"""

from .middleware import (
    AuthContext,
    FastMCPAuthWrapper,
    MCPAuthMiddleware,
    auth_required,
)
from .oauth import OAuthConfig, OAuthProvider
from .policy import PolicyEngine, ToolPolicy, create_default_policies

__version__ = "0.1.0"
__all__ = [
    "OAuthProvider",
    "OAuthConfig",
    "AuthContext",
    "auth_required",
    "create_default_policies",
    "MCPAuthMiddleware",
    "FastMCPAuthWrapper",
    "PolicyEngine",
    "ToolPolicy",
]
