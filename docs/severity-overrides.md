# Severity Override Policy

MCP Agent Security Kit assigns default severities for common MCP and agentic-tool risks. Some organizations need a controlled way to raise or lower specific rules for their environment, audit requirements, or sandbox boundaries. Severity override policies provide that mechanism without changing rule logic or removing evidence.

## Why Use Overrides

Use severity overrides when local policy is stricter or narrower than the default rule model. Examples include:

- Raising package-runner drift to `high` in production agent environments.
- Raising missing owner metadata to `medium` when every MCP server must have an accountable risk owner.
- Lowering a read-write filesystem warning for an isolated disposable lab environment.
- Keeping a documented exception visible while still allowing the pipeline to pass.

Overrides should be reviewed like code. Do not use them to hide findings.

## Policy Format

Use `examples/severity-overrides.json` as a starting point.

```json
{
  "overrides": [
    {
      "rule_id": "MCP-004",
      "severity": "high",
      "reason": "Package-runner drift is treated as high risk in production agent environments."
    },
    {
      "server": "local-research",
      "rule_id": "MCP-010",
      "severity": "low",
      "reason": "Read-write workspace access is approved for an isolated non-production research sandbox."
    }
  ]
}
```

Each entry supports:

| Field | Purpose |
| --- | --- |
| `rule_id` | Rule to override, such as `MCP-004`. |
| `server` | Optional exact server name. When set, the override applies only to that server and rule. |
| `severity` | One of `low`, `medium`, `high`, or `critical`. |
| `reason` | Review note explaining why the local policy differs from the default. |

Server-specific overrides take precedence over rule-wide overrides.

## Run With Overrides

```bash
python -m mcp_agent_security_kit.audit examples/mcp-config-risky.json --severity-overrides examples/severity-overrides.json
```

Use overrides with release gates:

```bash
python -m mcp_agent_security_kit.audit examples/mcp-config-risky.json --severity-overrides examples/severity-overrides.json --fail-on high
```

The report keeps the original finding message and evidence, then appends a note that severity was overridden by local policy.

## Governance Guidance

- Store override policies in source control with code owner review.
- Require a reason for every override.
- Prefer raising severity for production and externally connected agents.
- Time-box overrides that lower severity for temporary exceptions.
- Revisit policies when MCP servers, tools, network reachability, or credential handling changes.
