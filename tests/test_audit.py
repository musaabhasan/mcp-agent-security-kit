import json
import unittest

from mcp_agent_security_kit.audit import audit_config, render_sarif, risk_score, should_fail


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

    def test_inline_secret_headers_are_flagged(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "remote": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "url": "https://mcp.example.com/sse",
                        "headers": {"Authorization": "Bearer committed-token-value"},
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-011", rule_ids)

    def test_header_secret_placeholders_are_allowed(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "remote": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "url": "https://mcp.example.com/sse",
                        "headers": {"Authorization": "Bearer ${MCP_REMOTE_TOKEN}"},
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("MCP-011", rule_ids)

    def test_empty_auth_header_does_not_satisfy_remote_auth(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "remote": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "url": "https://mcp.example.com/sse",
                        "headers": {"Authorization": " "},
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-002", rule_ids)

    def test_inline_secret_arguments_are_flagged(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "remote-wrapper": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "node",
                        "args": ["server.js", "--api-key", "committed-secret-value"],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-012", rule_ids)

    def test_secret_argument_placeholders_are_allowed(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "remote-wrapper": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "node",
                        "args": ["server.js", "--api-key", "${MCP_API_KEY}"],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("MCP-012", rule_ids)

    def test_inline_url_query_secrets_are_flagged(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "remote": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "url": "https://mcp.example.com/sse?token=committed-token-value",
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-013", rule_ids)

    def test_url_query_secret_placeholders_are_allowed(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "remote": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "url": "https://mcp.example.com/sse?token=${MCP_REMOTE_TOKEN}",
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("MCP-013", rule_ids)

    def test_inline_url_userinfo_credentials_are_flagged(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "remote": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "url": "https://mcp-user:committed-password@mcp.example.com/sse",
                        "headers": {"Authorization": "Bearer ${MCP_REMOTE_TOKEN}"},
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-014", rule_ids)

    def test_url_without_userinfo_credentials_is_allowed(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "remote": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "url": "https://mcp.example.com/sse",
                        "headers": {"Authorization": "Bearer ${MCP_REMOTE_TOKEN}"},
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("MCP-014", rule_ids)

    def test_disabled_tls_validation_is_flagged(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "remote": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "url": "https://mcp.example.com/sse",
                        "headers": {"Authorization": "Bearer ${MCP_REMOTE_TOKEN}"},
                        "verify_ssl": False,
                    },
                    "proxy-wrapper": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "node",
                        "args": ["server.js", "--skip-tls-verify"],
                        "env": {"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
                    },
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-015", rule_ids)

    def test_normal_tls_validation_config_is_allowed(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "remote": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "url": "https://mcp.example.com/sse",
                        "headers": {"Authorization": "Bearer ${MCP_REMOTE_TOKEN}"},
                        "verify_ssl": True,
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("MCP-015", rule_ids)

    def test_sarif_output_contains_rules_and_results(self):
        findings = audit_config({"mcpServers": {"remote": {"url": "http://example.test/sse"}}})
        report = json.loads(render_sarif(findings))
        self.assertEqual(report["version"], "2.1.0")
        run = report["runs"][0]
        rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        result_ids = {result["ruleId"] for result in run["results"]}
        self.assertIn("MCP-001", rule_ids)
        self.assertIn("MCP-001", result_ids)
        self.assertTrue(all(result["level"] in {"note", "warning", "error"} for result in run["results"]))
        security_severities = [rule["properties"]["security-severity"] for rule in run["tool"]["driver"]["rules"]]
        self.assertTrue(all(0.0 <= float(value) <= 10.0 for value in security_severities))


if __name__ == "__main__":
    unittest.main()
