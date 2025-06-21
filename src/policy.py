"""
Authorization policy engine for MCP tools
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class PolicyAction(Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class ToolPolicy:
    """Policy rule for MCP tool access"""

    tool_pattern: str  # regex pattern for tool names
    required_scopes: list[str]
    action: PolicyAction = PolicyAction.ALLOW
    conditions: dict[str, Any] | None = None

    def matches_tool(self, tool_name: str) -> bool:
        """Check if the policy applies to given tool"""
        return bool(re.match(self.tool_pattern, tool_name))

    def evaluate_scopes(self, user_scopes: list[str]) -> bool:
        """Check if user has required scopes"""
        return all(scope in user_scopes for scope in self.required_scopes)


class PolicyEngine:
    """Authorization policy engine"""

    def __init__(self):
        self.policies: list[ToolPolicy] = []
        self.default_action = PolicyAction.DENY

    def add_policy(self, policy: ToolPolicy):
        """Add a policy rule"""
        self.policies.append(policy)

    def add_tool_scope_policy(
        self,
        tool_pattern: str,
        required_scopes: str | list[str],
        action: PolicyAction = PolicyAction.ALLOW,
    ):
        """Convenience method to add tool-scope policy"""
        if isinstance(required_scopes, str):
            required_scopes = [required_scopes]

        policy = ToolPolicy(
            tool_pattern=tool_pattern, required_scopes=required_scopes, action=action
        )
        self.add_policy(policy)

    def authorize_tool_call(
        self,
        tool_name: str,
        user_scopes: list[str],
        user_claims: dict[str, Any] | None = None,
    ) -> tuple[bool, str | None]:
        """
        Authorize a tool call

        Returns:
            (authorized: bool, reason: Optional[str])
        """

        matching_policies = [
            policy for policy in self.policies if policy.matches_tool(tool_name)
        ]

        if not matching_policies:
            if self.default_action == PolicyAction.ALLOW:
                return True, None
            else:
                return False, f"No policy found for tool '{tool_name}', default deny"

        for policy in matching_policies:
            if policy.action == PolicyAction.DENY:
                if policy.evaluate_scopes(user_scopes):
                    return False, f"Explicit deny policy for tool '{tool_name}'"

        allow_policies = [
            p for p in matching_policies if p.action == PolicyAction.ALLOW
        ]

        if not allow_policies:
            return False, f"No allow policies found for tool '{tool_name}'"

        for policy in allow_policies:
            if policy.evaluate_scopes(user_scopes):
                if self._evaluate_conditions(policy.conditions, user_claims):
                    return True, None

        return False, f"Insufficient scopes for tool '{tool_name}'"

    def _evaluate_conditions(
        self,
        conditions: dict[str, Any] | None,
        user_claims: dict[str, Any] | None,
    ) -> bool:
        """Evaluate additional policy conditions"""

        if not conditions:
            return True

        if not user_claims:
            return False

        for key, expected_value in conditions.items():
            user_value = user_claims.get(key)

            if isinstance(expected_value, list):
                if user_value not in expected_value:
                    return False
            elif user_value != expected_value:
                return False

        return True

    def get_allowed_tools(self, user_scopes: list[str]) -> list[str]:
        """Get list of tools user is allowed to call"""

        allowed_tools = []

        for policy in self.policies:
            if policy.action == PolicyAction.ALLOW and policy.evaluate_scopes(
                user_scopes
            ):
                allowed_tools.append(policy.tool_pattern)

        return allowed_tools


def create_default_policies() -> PolicyEngine:
    """Create a default policy set for MCP servers"""

    engine = PolicyEngine()

    engine.add_tool_scope_policy(".*", ["mcp:tools:*"])

    engine.add_tool_scope_policy("read_.*", ["mcp:tools:read"])

    engine.add_tool_scope_policy("write_.*", ["mcp:tools:write"])

    engine.add_tool_scope_policy("admin_.*", ["mcp:tools:admin"])

    return engine
