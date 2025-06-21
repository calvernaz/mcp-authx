"""
Example usage of the MCP Auth toolkit

This file demonstrates 3 different integration patterns for adding OAuth authentication
to MCP servers. Each pattern has different trade-offs and use cases.
"""

import asyncio

from src import (
    AuthContext,
    MCPAuthMiddleware,
    OAuthConfig,
    OAuthProvider,
    PolicyEngine,
    auth_required,
)


async def example_standalone_usage():
    """Example of using the auth components standalone

    This demonstrates the LOW-LEVEL approach where you manually create
    OAuth providers and policy engines, then apply decorators to individual
    functions. This gives you fine-grained control over each tool's authentication.

    Use this approach when:
    - You have a custom MCP server implementation
    - You want per-function control over auth settings
    - You need different OAuth providers for different tools
    - You're building auth into an existing codebase function by function
    """

    config = OAuthConfig(
        client_id="your-client-id",
        client_secret="your-client-secret",
        authorization_endpoint="https://auth.example.com/oauth/authorize",
        token_endpoint="https://auth.example.com/oauth/token",
        scopes=["mcp:tools:read", "mcp:tools:write"],
    )

    oauth_provider = OAuthProvider(config, "your-jwt-secret")
    policy_engine = PolicyEngine()

    # Set up granular policies - different tools need different scopes
    policy_engine.add_tool_scope_policy("read_.*", ["mcp:tools:read"])
    policy_engine.add_tool_scope_policy("write_.*", ["mcp:tools:write"])

    # Define individual functions and protect each with @auth_required decorator
    # Notice: Each function explicitly specifies its tool name for policy matching

    @auth_required(oauth_provider, policy_engine, "read_files")  # ← Explicit tool name
    async def read_files(auth_context: AuthContext, path: str):
        """Protected tool that requires read scope

        The decorator:
        1. Intercepts the call
        2. Validates the Authorization header
        3. Checks if user has 'mcp:tools:read' scope
        4. Injects AuthContext as first parameter
        """
        print(f"Reading files for user: {auth_context.user_id}")
        return {"files": ["file1.txt", "file2.txt"], "path": path}

    @auth_required(oauth_provider, policy_engine, "write_data")  # ← Different tool name
    async def write_data(auth_context: AuthContext, data: dict):
        """Protected tool that requires write scope

        This function needs 'mcp:tools:write' scope due to the policy:
        policy_engine.add_tool_scope_policy("write_.*", ["mcp:tools:write"])
        """
        print(f"Writing data for user: {auth_context.user_id}")
        return {"status": "written", "data": data}

    # === DEMO: Generate OAuth flow ===
    # This shows how a client would start the OAuth process
    auth_url, pkce = oauth_provider.generate_authorization_url(
        redirect_uri="http://localhost:8080/callback", scopes=["mcp:tools:read"]
    )

    print(f"🔗 Authorization URL: {auth_url}")
    print(f"🔑 PKCE Verifier: {pkce.verifier}")
    print("📋 In real usage: Client visits URL, authorizes, gets redirected with code")

    # === DEMO: Policy Engine Testing ===
    # Test different tools with limited scopes to show policy enforcement
    print("\n🛡️  Policy Engine Demo (user has only 'mcp:tools:read'):")
    test_scopes = ["mcp:tools:read"]  # Simulating a read-only user

    for tool in ["read_files", "write_data", "admin_delete"]:
        authorized, reason = policy_engine.authorize_tool_call(tool, test_scopes)
        status = "✅ ALLOWED" if authorized else "❌ DENIED"
        print(f"  {tool}: {status} ({reason or 'sufficient scopes'})")

    print("\n💡 Notice: Only 'read_files' is allowed because user lacks write/admin scopes")


def example_decorator_usage():
    """Example of using the auth decorator with automatic tool name detection

    This demonstrates a SIMPLIFIED approach where the decorator automatically
    uses the function name as the tool name for policy matching.

    Key differences from standalone usage:
    - No explicit tool name in @auth_required() - uses function name
    - More concise setup
    - Less granular control

    Use this approach when:
    - Your function names match your intended tool names
    - You want cleaner, more readable decorators
    - You have consistent naming conventions
    - You prefer convention over configuration
    """

    config = OAuthConfig(
        client_id="demo-client",
        client_secret="demo-secret",
        authorization_endpoint="https://auth.example.com/oauth/authorize",
        token_endpoint="https://auth.example.com/oauth/token",
    )

    oauth_provider = OAuthProvider(config, "demo-jwt-secret")
    policy_engine = PolicyEngine()
    # Wildcard policy - any tool name matches, requires generic 'mcp:tools' scope
    policy_engine.add_tool_scope_policy(".*", ["mcp:tools"])

    # Notice: No explicit tool name - decorator uses function name automatically
    @auth_required(oauth_provider, policy_engine)  # ← No tool name parameter!
    async def my_protected_tool(auth_context: AuthContext, message: str):
        """Tool protected by OAuth

        The decorator automatically uses 'my_protected_tool' as the tool name
        for policy matching against the pattern ".*" which requires "mcp:tools" scope.
        """
        return {
            "message": f"Hello {auth_context.user_id}: {message}",
            "scopes": auth_context.scopes,
        }

    print("🔐 Decorator example configured")
    print("   Tool 'my_protected_tool' now requires OAuth token")
    print("   🔍 Policy match: '.*' pattern catches all tool names")
    print("   🎫 Required scope: 'mcp:tools' (from policy rule)")


async def example_manual_middleware():
    """Example of using the middleware manually (most flexible)
    This demonstrates the MANUAL approach where you create middleware
    instances and call authentication/authorization methods directly.

    Use this approach when:
    - You need maximum control over the auth flow
    - You're integrating with existing middleware systems
    - You want to handle errors and edge cases manually
    - You're building custom MCP server implementations
    """


    config = OAuthConfig(
        client_id="manual-client",
        client_secret="manual-secret",
        authorization_endpoint="https://auth.example.com/oauth/authorize",
        token_endpoint="https://auth.example.com/oauth/token",
    )

    oauth_provider = OAuthProvider(config, "manual-jwt-secret")
    policy_engine = PolicyEngine()
    policy_engine.add_tool_scope_policy(".*", ["mcp:tools"])

    # Create middleware instance
    middleware = MCPAuthMiddleware(oauth_provider, policy_engine)

    # Simulate incoming request with Authorization header
    fake_auth_header = "Bearer fake-jwt-token-here"

    # Manual authentication (you handle the result)
    auth_context = middleware.authenticate_request(fake_auth_header)

    if auth_context:
        print(f"✅ Authenticated user: {auth_context.user_id}")

        # Manual authorization check (you handle the result)
        authorized, reason = middleware.authorize_tool_call("some_tool", auth_context)

        if authorized:
            print("✅ Authorized to call 'some_tool'")
            # Your tool logic here
        else:
            print(f"❌ Access denied: {reason}")
    else:
        print("❌ Authentication failed")

    print("\n💡 Manual approach gives you complete control over error handling")


if __name__ == "__main__":
    print("🚀 MCP Auth Toolkit - Integration Pattern Examples\n")
    print("These examples show 3 different ways to integrate authentication:\n")

    print("1️⃣ STANDALONE USAGE (Function-by-function control):")
    print("   • Manual OAuth provider and policy setup")
    print("   • @auth_required decorator with explicit tool names")
    print("   • Each function has its own auth configuration")
    asyncio.run(example_standalone_usage())

    print("\n" + "="*60 + "\n")

    print("2️⃣ DECORATOR USAGE (Convention over configuration):")
    print("   • @auth_required uses function name as tool name")
    print("   • Cleaner syntax, less explicit configuration")
    print("   • Good for consistent naming conventions")
    example_decorator_usage()

    print("\n" + "="*60 + "\n")

    print("3️⃣ MANUAL MIDDLEWARE (Maximum control):")
    print("   • Direct middleware usage")
    print("   • Custom error handling")
    print("   • Integration with existing systems")
    asyncio.run(example_manual_middleware())

    print("\n" + "="*60 + "\n")
    print("✨ Choose the pattern that best fits your architecture!")
    print("\n📚 For FastMCP integration, see demo_server.py")
    print("🔧 For production setup, configure real OAuth providers")
