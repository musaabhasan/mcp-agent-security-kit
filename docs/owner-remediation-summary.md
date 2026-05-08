# Owner Remediation Summary

Security scans are easier to act on when findings are routed to accountable
owners. The audit CLI can append a Markdown remediation summary grouped by
`riskOwner`, `risk_owner`, `owner`, or `maintainer` metadata from the MCP server
configuration.

## Run The Summary

```bash
python -m mcp_agent_security_kit.audit examples/mcp-config-risky.json --append-owner-summary
```

Write the report to a file:

```bash
python -m mcp_agent_security_kit.audit examples/mcp-config-risky.json --append-owner-summary --output reports/mcp-audit-with-owners.md
```

## Owner Resolution

The summary uses the first available value in this order:

1. `riskOwner`
2. `risk_owner`
3. `owner`
4. `maintainer`
5. `unassigned`

This lets teams distinguish the person or group that runs the MCP server from
the person or group accountable for the risk decision.

## Output Structure

The summary includes:

- a high-level owner table with critical, high, medium, and low counts,
- an action recommendation based on the highest severity for that owner,
- and per-owner tables listing rule id, server, finding, and recommendation.

Use the owner summary in pull requests, change records, exception reviews, and
pilot readiness reports. Findings with `unassigned` ownership should normally
be fixed before production rollout because missing ownership slows incident
response and remediation.

