import unittest

from mcp_agent_security_kit.audit import audit_config, risk_score, should_fail


class AuditTests(unittest.TestCase):
    def test_risky_config_detects_expected_findings(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
                        "env": {"API_TOKEN": "secret"},
                    },
                    "remote": {"url": "http://example.test/sse"},
                    "shell": {"command": "bash", "args": ["-lc", "echo test"]},
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-001", rule_ids)
        self.assertIn("MCP-002", rule_ids)
        self.assertIn("MCP-003", rule_ids)
        self.assertIn("MCP-004", rule_ids)
        self.assertIn("MCP-005", rule_ids)
        self.assertIn("MCP-007", rule_ids)
        self.assertGreaterEqual(risk_score(findings), 80)

    def test_safer_config_has_no_high_findings(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "docs-reader": {
                        "owner": "security",
                        "riskOwner": "ai-owner",
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "./docs", "--read-only"],
                    },
                    "remote": {
                        "owner": "platform",
                        "riskOwner": "api-owner",
                        "url": "https://mcp.example.com/sse",
                        "headers": {"Authorization": "Bearer ${TOKEN}"},
                    },
                }
            }
        )
        self.assertFalse(should_fail(findings, "high"))

    def test_empty_config_returns_configuration_finding(self):
        findings = audit_config({})
        self.assertEqual(findings[0].rule_id, "MCP-000")


if __name__ == "__main__":
    unittest.main()
