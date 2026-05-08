import json
from pathlib import Path
import unittest

from mcp_agent_security_kit.audit import (
    audit_config,
    compare_allowed_tool_drift,
    extract_allowed_tools,
    render_allowed_tool_drift_json,
    render_allowed_tool_drift_markdown,
    render_json,
    render_owner_remediation_summary,
    render_sarif,
    risk_score,
    should_fail,
)


ROOT = Path(__file__).resolve().parents[1]


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

    def test_docker_socket_mount_is_flagged(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "docker-tools": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "docker",
                        "args": [
                            "run",
                            "--mount",
                            "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock",
                            "example/mcp:latest",
                        ],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-016", rule_ids)

    def test_windows_docker_engine_pipe_is_flagged(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "windows-docker-tools": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "docker",
                        "args": [
                            "run",
                            "-v",
                            "//./pipe/docker_engine://./pipe/docker_engine",
                            "example/mcp:latest",
                        ],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-016", rule_ids)

    def test_mutable_docker_image_reference_is_flagged(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "containerized-tool": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "docker",
                        "args": [
                            "run",
                            "--rm",
                            "--name",
                            "mcp-tool",
                            "--mount",
                            "type=bind,source=/safe/docs,target=/docs,readonly",
                            "example/mcp-server:latest",
                        ],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-018", rule_ids)

    def test_digest_pinned_docker_image_reference_is_allowed(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "containerized-tool": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "docker",
                        "args": [
                            "container",
                            "run",
                            "--rm",
                            "example/mcp-server@sha256:"
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        ],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("MCP-018", rule_ids)

    def test_auto_approval_wildcard_is_flagged(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "workspace-agent": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "node",
                        "args": ["server.js"],
                        "alwaysAllow": ["read_file", "*"],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-017", rule_ids)

    def test_explicit_auto_approval_tools_are_allowed(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "workspace-agent": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "node",
                        "args": ["server.js"],
                        "alwaysAllow": ["read_file", "search_docs"],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("MCP-017", rule_ids)

    def test_external_action_auto_approval_is_flagged(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "helpdesk-agent": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "node",
                        "args": ["server.js"],
                        "alwaysAllow": ["search_docs", "create_ticket", "send_email", "merge_pull_request"],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        external_action_finding = next(finding for finding in findings if finding.rule_id == "MCP-023")

        self.assertIn("MCP-023", rule_ids)
        self.assertIn("create_ticket", external_action_finding.evidence)
        self.assertIn("send_email", external_action_finding.evidence)
        self.assertIn("merge_pull_request", external_action_finding.evidence)

    def test_read_only_auto_approval_tools_do_not_trigger_external_action_rule(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "research-agent": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "node",
                        "args": ["server.js"],
                        "alwaysAllow": ["read_file", "search_docs", "list_resources"],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("MCP-023", rule_ids)

    def test_broad_auth_scope_is_flagged(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "github-agent": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "url": "https://mcp.example.com/sse",
                        "headers": {"Authorization": "Bearer ${MCP_REMOTE_TOKEN}"},
                        "auth": {"oauthScopes": ["repo:read", "admin:org", "delete:packages"]},
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-019", rule_ids)

    def test_narrow_auth_scopes_are_allowed(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "github-agent": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "url": "https://mcp.example.com/sse",
                        "headers": {"Authorization": "Bearer ${MCP_REMOTE_TOKEN}"},
                        "auth": {"oauthScopes": ["read:issues", "read:pull_requests"]},
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("MCP-019", rule_ids)

    def test_sensitive_credential_paths_are_flagged(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "filesystem": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "npx",
                        "args": [
                            "-y",
                            "@modelcontextprotocol/server-filesystem@1.0.0",
                            "C:\\Users\\alice\\.ssh",
                            "~/.aws",
                            "/home/alice/.kube/config",
                        ],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-020", rule_ids)

    def test_project_paths_do_not_trigger_sensitive_credential_rule(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "workspace": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "npx",
                        "args": [
                            "-y",
                            "@modelcontextprotocol/server-filesystem@1.0.0",
                            "./docs",
                            "./src",
                            "--read-only",
                        ],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("MCP-020", rule_ids)

    def test_env_files_are_flagged(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "runtime": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "node",
                        "args": [
                            "server.js",
                            "--env-file=.env.production",
                            "--dotenv",
                            "./secrets.env",
                        ],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-021", rule_ids)

    def test_sample_env_files_are_allowed(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "runtime": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "node",
                        "args": [
                            "server.js",
                            "--env-file",
                            ".env.example",
                            "./sample.env",
                        ],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("MCP-021", rule_ids)

    def test_browser_profile_paths_are_flagged(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "browser": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "node",
                        "args": [
                            "browser-server.js",
                            "--user-data-dir",
                            "C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\User Data",
                            "--cookie-file=./cookies.json",
                        ],
                    },
                    "firefox": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "python",
                        "args": [
                            "server.py",
                            "/home/alice/.mozilla/firefox/default-release/cookies.sqlite",
                        ],
                    },
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("MCP-022", rule_ids)

    def test_isolated_browser_profiles_are_allowed(self):
        findings = audit_config(
            {
                "mcpServers": {
                    "browser": {
                        "owner": "platform",
                        "riskOwner": "security",
                        "command": "node",
                        "args": [
                            "browser-server.js",
                            "--user-data-dir",
                            "./tmp/isolated-mcp-browser-profile",
                            "--storage-state",
                            "${MCP_BROWSER_STORAGE_STATE}",
                        ],
                    }
                }
            }
        )
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("MCP-022", rule_ids)

    def test_extract_allowed_tools_handles_lists_and_maps(self):
        tools = extract_allowed_tools(
            {
                "mcpServers": {
                    "workspace": {
                        "allowedTools": ["read_file", "search_docs"],
                        "alwaysAllow": {"write_file": True, "delete_file": False},
                    }
                }
            }
        )
        self.assertEqual(tools["workspace"], {"read_file", "search_docs", "write_file"})

    def test_allowed_tool_drift_flags_high_impact_additions(self):
        baseline = {
            "mcpServers": {
                "workspace": {
                    "owner": "platform",
                    "riskOwner": "security",
                    "allowedTools": ["read_file", "search_docs"],
                }
            }
        }
        current = {
            "mcpServers": {
                "workspace": {
                    "owner": "platform",
                    "riskOwner": "security",
                    "allowedTools": ["read_file", "search_docs", "write_file", "run_shell"],
                }
            }
        }

        drift = compare_allowed_tool_drift(baseline, current)
        drift_by_tool = {item.tool: item for item in drift}

        self.assertEqual(drift_by_tool["write_file"].severity, "high")
        self.assertEqual(drift_by_tool["run_shell"].change, "added")

    def test_allowed_tool_drift_flags_wildcard_as_critical(self):
        drift = compare_allowed_tool_drift(
            {"mcpServers": {"workspace": {"allowedTools": ["read_file"]}}},
            {"mcpServers": {"workspace": {"allowedTools": ["read_file", "*"]}}},
        )
        self.assertEqual(drift[0].severity, "critical")
        self.assertEqual(drift[0].tool, "*")

    def test_allowed_tool_drift_renderers(self):
        drift = compare_allowed_tool_drift(
            {"mcpServers": {"workspace": {"allowedTools": ["read_file", "search_docs"]}}},
            {"mcpServers": {"workspace": {"allowedTools": ["read_file", "write_file"]}}},
        )
        markdown = render_allowed_tool_drift_markdown(drift)
        json_report = json.loads(render_allowed_tool_drift_json(drift))

        self.assertIn("MCP Allowed Tool Drift", markdown)
        self.assertIn("write_file", markdown)
        self.assertEqual(len(json_report["drift"]), 2)

    def test_owner_remediation_summary_groups_by_risk_owner(self):
        config = {
            "mcpServers": {
                "workspace": {
                    "owner": "platform",
                    "riskOwner": "security",
                    "command": "bash",
                    "args": ["-lc", "echo test"],
                },
                "remote": {
                    "owner": "integrations",
                    "url": "http://example.test/sse",
                },
            }
        }
        findings = audit_config(config)
        summary = render_owner_remediation_summary(config, findings)

        self.assertIn("Owner Remediation Summary", summary)
        self.assertIn("| security |", summary)
        self.assertIn("| integrations |", summary)
        self.assertIn("Block release", summary)

    def test_owner_remediation_summary_handles_unassigned_configuration(self):
        findings = audit_config({})
        summary = render_owner_remediation_summary({}, findings)

        self.assertIn("| unassigned |", summary)
        self.assertIn("MCP-000", summary)

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

    def test_json_output_matches_published_contract(self):
        findings = audit_config({"mcpServers": {"remote": {"url": "http://example.test/sse"}}})
        report = json.loads(render_json(findings))
        schema = json.loads((ROOT / "schema" / "audit-output.schema.json").read_text(encoding="utf-8"))

        self.assertEqual(sorted(report.keys()), sorted(schema["required"]))
        self.assertIsInstance(report["risk_score"], int)
        self.assertGreaterEqual(report["risk_score"], schema["properties"]["risk_score"]["minimum"])
        self.assertLessEqual(report["risk_score"], schema["properties"]["risk_score"]["maximum"])
        self.assertIsInstance(report["findings"], list)

        finding_schema = schema["properties"]["findings"]["items"]
        required_fields = set(finding_schema["required"])
        severities = set(finding_schema["properties"]["severity"]["enum"])

        for finding in report["findings"]:
            self.assertEqual(set(finding), required_fields)
            self.assertIn(finding["severity"], severities)
            self.assertRegex(finding["rule_id"], finding_schema["properties"]["rule_id"]["pattern"])
            self.assertTrue(finding["server"])
            self.assertTrue(finding["message"])
            self.assertTrue(finding["recommendation"])
            self.assertIsInstance(finding["evidence"], str)


if __name__ == "__main__":
    unittest.main()
