# Contributing

Thank you for considering a contribution.

## Useful Contributions

- Add a new MCP configuration risk rule.
- Improve rule explanations or remediation guidance.
- Add safe and risky sample configurations.
- Map controls to security frameworks.
- Add tests for new configuration shapes.

## Development

Run tests:

```bash
python -m unittest discover -s tests
```

Run the auditor:

```bash
python -m mcp_agent_security_kit.audit examples/mcp-config-risky.json
```

## Pull Request Checklist

- The change does not include real secrets, customer data, or private URLs.
- New rules include a test.
- Documentation is updated when behavior changes.
- The PR explains the risk and the recommended remediation.
