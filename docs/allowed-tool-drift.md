# Allowed Tool Drift Comparison

MCP tool allowlists often start narrow and then expand as teams add workflows.
That expansion is a security-relevant change: a new allowed tool may grant file
writes, shell execution, ticket updates, deployment actions, outbound requests,
or credential access that was not part of the approved baseline.

This repository includes a dependency-free comparator for reviewing allowed-tool
changes between an approved baseline configuration and a current configuration.

## Why It Matters

Static MCP audits detect risky configuration in one file. Drift comparison adds a
change-control view:

- which allowed tools were added,
- which allowed tools were removed,
- whether newly allowed tools look high impact,
- whether wildcard approval appeared,
- and what approval or monitoring action should happen before rollout.

## Run The Comparator

```bash
python scripts/compare_allowed_tools.py examples/allowed-tools-baseline.json examples/allowed-tools-current.json
```

Write JSON for CI or dashboards:

```bash
python scripts/compare_allowed_tools.py examples/allowed-tools-baseline.json examples/allowed-tools-current.json --format json --output reports/allowed-tool-drift.json
```

Fail a pipeline on high-impact drift:

```bash
python scripts/compare_allowed_tools.py baseline.json current.json --fail-on high
```

## Severity Model

| Severity | Signal | Expected response |
| --- | --- | --- |
| Critical | Wildcard approval such as `*`, `all`, or `any` was added | Block release until explicit tool names replace the wildcard. |
| High | Added tool name suggests write, delete, shell, deploy, send, request, token, secret, upload, or similar authority | Require owner approval, runtime monitoring, and a rollback path. |
| Medium | A lower-impact allowed tool was added | Confirm workflow need and record the change owner. |
| Low | A tool was removed | Confirm dependent workflows no longer require it. |

## CI Review Pattern

1. Store the approved MCP configuration baseline in a protected branch, release
   artifact, or governance repository.
2. Run the comparator against the current pull request configuration.
3. Fail on `high` or `critical` drift.
4. Attach the Markdown or JSON report to the change record.
5. Require security or risk-owner sign-off before allowing new high-impact tools.

Allowed-tool drift does not replace the main audit CLI. Use both controls
together: the audit CLI evaluates the current configuration, while the drift
comparator evaluates how the allowed tool boundary changed.

