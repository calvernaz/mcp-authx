# MCP Auth Toolkit

A Python library for adding OAuth 2.1 + PKCE authentication and fine-grained authorization to Model Context Protocol (MCP) servers.

## Not Ready for Production

## Features

- 🔐 **OAuth 2.1 + PKCE**: Secure authorization code flow with PKCE support
- 🎯 **Fine-grained Authorization**: Tool-level permissions with configurable policies  
- 🔧 **Embeddable**: Works as middleware or decorators in existing MCP servers
- 🚀 **Runtime-agnostic**: Compatible with FastMCP, custom servers, and frameworks
- 🛡️ **JWT-based**: Short-lived tokens with tool-scoped claims
- 📋 **Policy Engine**: Declarative RBAC with regex pattern matching

## Quick Start

### Installation

#### Using uv (recommended)

```bash
# Install the package
uv add mcp-auth-toolkit

# Or install with FastMCP support
uv add mcp-auth-toolkit[fastmcp]

# For development
git clone https://github.com/your-org/mcp-auth-toolkit
cd mcp-auth-toolkit
uv sync --group dev
```

#### Using pip

```bash
pip install mcp-auth-toolkit
# or with FastMCP support
pip install mcp-auth-toolkit[fastmcp]
```

### Basic Usage

```python
from src import OAuthProvider, OAuthConfig, PolicyEngine, auth_required

# Configure OAuth provider
config = OAuthConfig(
    client_id="your-client-id",
    client_secret="your-client-secret",
    authorization_endpoint="https://auth.example.com/oauth/authorize",
    token_endpoint="https://auth.example.com/oauth/token",
    scopes=["mcp:tools:read", "mcp:tools:write"]
)

oauth_provider = OAuthProvider(config, "your-jwt-secret")
policy_engine = PolicyEngine()

# Define tool permissions
policy_engine.add_tool_scope_policy("read_.*", ["mcp:tools:read"])
policy_engine.add_tool_scope_policy("write_.*", ["mcp:tools:write"])


# Protect MCP tools with decorators
@auth_required(oauth_provider, policy_engine, "read_files")
async def read_files(auth_context, path: str):
    return {"files": ["file1.txt"], "user": auth_context.user_id}
```

### FastMCP Integration

```python
from mcp.server.fastmcp import FastMCP
from src import FastMCPAuthWrapper, create_default_policies

mcp = FastMCP("My Secure Server")


# Add your tools
@mcp.tool()
def my_tool(data: str):
    return {"result": data}


# Wrap with authentication
oauth_provider = OAuthProvider(config, jwt_secret)
policy_engine = create_default_policies()
auth_wrapper = FastMCPAuthWrapper(mcp, oauth_provider, policy_engine)
auth_wrapper.add_auth_endpoints()
```

## Architecture

### OAuth Flow

1. **Authorization**: Generate PKCE-enabled authorization URL
2. **Token Exchange**: Exchange authorization code for JWT access token
3. **Tool Access**: Validate token and check tool permissions
4. **Introspection**: Verify token validity and extract claims

### Policy Engine

The policy engine supports:
- **Regex patterns** for tool name matching
- **Scope-based authorization** with required claims
- **Conditional policies** based on user attributes
- **Default deny** with explicit allow rules

### Token Structure

JWT tokens include:
- Standard claims (`iss`, `sub`, `aud`, `exp`)
- `mcp_tool_scopes`: Array of allowed tool scopes
- `upstream_token`: Original OAuth provider token

## Configuration

### Environment Variables

```bash
OAUTH_CLIENT_ID=your-client-id
OAUTH_CLIENT_SECRET=your-client-secret
OAUTH_AUTH_ENDPOINT=https://auth.example.com/oauth/authorize
OAUTH_TOKEN_ENDPOINT=https://auth.example.com/oauth/token
JWT_SECRET=your-jwt-signing-secret
```

### Policy Examples

```python
# Allow read tools for users with read scope
policy_engine.add_tool_scope_policy("get_.*", ["mcp:tools:read"])

# Require admin scope for delete operations  
policy_engine.add_tool_scope_policy("delete_.*", ["mcp:tools:admin"])

# Wildcard access for superusers
policy_engine.add_tool_scope_policy(".*", ["mcp:tools:*"])
```

## Demo Server

Run the included demo server:

```bash
# Using uv
uv run demo_server.py

# Or install with examples and run via script
uv sync --extra examples
uv run mcp-auth-demo

# Using pip
python demo_server.py
```

Available endpoints:
- `get_weather` (requires: `mcp:tools:read`)
- `send_email` (requires: `mcp:tools:write`)
- `delete_user` (requires: `mcp:tools:admin`)
- `oauth://authorize` (OAuth authorization)
- `oauth_token` (Token exchange)
- `oauth_introspect` (Token validation)

## Security Features

- **PKCE**: Prevents authorization code interception
- **Short-lived tokens**: 1-hour expiration by default
- **Scope validation**: Tools require specific scopes
- **Token introspection**: Real-time validation
- **Revocation support**: Invalidate compromised tokens

## Integration Patterns

### 1. Decorator Pattern
```python
@auth_required(oauth_provider, policy_engine, "tool_name")
async def my_tool(auth_context, ...):
    pass
```

### 2. Middleware Pattern
```python
auth_wrapper = FastMCPAuthWrapper(mcp_server, oauth_provider, policy_engine)
```

### 3. Manual Pattern
```python
middleware = MCPAuthMiddleware(oauth_provider, policy_engine)
auth_context = middleware.authenticate_request(auth_header)
authorized, reason = middleware.authorize_tool_call(tool_name, auth_context)
```

## Contributing

This toolkit follows the MCP specification for authentication and implements OAuth 2.1 best practices. Contributions welcome for:

- Additional identity provider integrations
- Policy engine enhancements  
- Transport layer improvements
- Documentation and examples

## License

MIT License - see LICENSE file for details.