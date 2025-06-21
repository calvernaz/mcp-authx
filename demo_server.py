"""
Demo MCP server with embedded OAuth authentication
"""

import os
import secrets

from mcp.server.fastmcp import FastMCP

from src import (
    AuthContext,
    FastMCPAuthWrapper,
    OAuthConfig,
    OAuthProvider,
    create_default_policies,
)


def create_demo_server():
    """Create a demo MCP server with OAuth authentication"""

    mcp = FastMCP("Secure Demo MCP Server")

    oauth_config = OAuthConfig(
        client_id=os.getenv("OAUTH_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("OAUTH_CLIENT_SECRET", "demo-secret"),
        authorization_endpoint=os.getenv(
            "OAUTH_AUTH_ENDPOINT", "https://auth.example.com/oauth/authorize"
        ),
        token_endpoint=os.getenv(
            "OAUTH_TOKEN_ENDPOINT", "https://auth.example.com/oauth/token"
        ),
        scopes=["mcp:tools:read", "mcp:tools:write", "mcp:tools:admin"],
    )

    jwt_secret = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
    oauth_provider = OAuthProvider(oauth_config, jwt_secret)

    policy_engine = create_default_policies()

    policy_engine.add_tool_scope_policy("get_weather", ["mcp:tools:read"])
    policy_engine.add_tool_scope_policy("send_email", ["mcp:tools:write"])
    policy_engine.add_tool_scope_policy("delete_.*", ["mcp:tools:admin"])

    @mcp.tool()
    def get_weather(location: str, auth_context: AuthContext = None) -> dict:
        """Get weather information for a location (requires read scope)"""
        if auth_context:
            print(f"Weather request by user: {auth_context.user_id}")

        return {
            "location": location,
            "temperature": "22°C",
            "condition": "Sunny",
            "requested_by": auth_context.user_id if auth_context else "anonymous",
        }

    @mcp.tool()
    def send_email(
        to: str, subject: str, body: str, auth_context: AuthContext = None
    ) -> dict:
        """Send an email (requires write scope)"""
        if auth_context:
            print(f"Email send request by user: {auth_context.user_id}")

        return {
            "status": "sent",
            "to": to,
            "subject": subject,
            "sent_by": auth_context.user_id if auth_context else "anonymous",
        }

    @mcp.tool()
    def delete_user(user_id: str, auth_context: AuthContext = None) -> dict:
        """Delete a user (requires admin scope)"""
        if auth_context:
            print(f"User deletion request by admin: {auth_context.user_id}")

        return {
            "status": "deleted",
            "user_id": user_id,
            "deleted_by": auth_context.user_id if auth_context else "anonymous",
        }

    @mcp.resource("info://server")
    def server_info() -> dict:
        """Get server information (public endpoint)"""
        return {
            "name": "Secure Demo MCP Server",
            "version": "1.0.0",
            "auth_enabled": True,
            "supported_scopes": oauth_config.scopes,
        }

    auth_wrapper = FastMCPAuthWrapper(mcp, oauth_provider, policy_engine)
    auth_wrapper.add_auth_endpoints()

    return mcp


def main():
    """Main entry point for the demo server"""
    server = create_demo_server()

    print("🔐 Secure MCP Server starting...")
    print("📋 Available tools:")
    print("  - get_weather (requires: mcp:tools:read)")
    print("  - send_email (requires: mcp:tools:write)")
    print("  - delete_user (requires: mcp:tools:admin)")
    print("🔧 OAuth endpoints:")
    print("  - oauth://authorize")
    print("  - oauth_token")
    print("  - oauth_introspect")
    print("  - oauth_revoke")

    server.run()


if __name__ == "__main__":
    main()
