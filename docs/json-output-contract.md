# JSON Output Contract

The audit CLI can produce machine-readable JSON for security dashboards, CI gates, ticket automation, and evidence repositories.

```bash
python -m mcp_agent_security_kit.audit examples/mcp-config-risky.json --format json --output reports/mcp-audit.json
python scripts/validate_json_output.py reports/mcp-audit.json
```

The published contract lives at [`schema/audit-output.schema.json`](../schema/audit-output.schema.json). It is intentionally small so downstream systems can consume audit results without depending on internal Python objects.

## Top-Level Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `risk_score` | integer | Total score from 0 to 100, based on finding severity. |
| `findings` | array | Ordered list of configuration findings. |

## Finding Fields

| Field | Type | Meaning |
| --- | --- | --- |
| `severity` | enum | One of `low`, `medium`, `high`, or `critical`. |
| `rule_id` | string | Stable detector identifier such as `MCP-015`. |
| `server` | string | MCP server name or configuration scope. |
| `message` | string | Short description of the issue. |
| `recommendation` | string | Remediation guidance suitable for tickets or review records. |
| `evidence` | string | Sanitized configuration evidence, when available. |

## Integration Guidance

- Treat `rule_id` as the stable key for suppressions, ticket routing, and trend reporting.
- Treat `severity` and `risk_score` as policy inputs, not as the only review criteria.
- Store the JSON report with the reviewed MCP configuration version so later reviewers can reconstruct the risk decision.
- Avoid placing raw secrets in MCP configuration files. The auditor tries to identify inline secrets, but reports should still be handled as security-sensitive evidence.

## Compatibility Policy

The JSON contract is designed for additive evolution. Future versions should avoid removing required fields or changing existing field meanings without a documented migration note.
