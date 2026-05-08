# Cloud Metadata Exposure

Rule `MCP-024` flags MCP servers whose configuration can expose cloud metadata services to an agent-accessible network tool. This usually appears in browser, fetch, request, crawler, or HTTP tools that accept broad egress allowlists, wildcard destinations, or explicit metadata endpoints such as `169.254.169.254`.

Cloud metadata endpoints often provide instance identity documents, role credentials, tokens, tags, project metadata, and workload identity hints. If an agent can be prompted into making arbitrary network requests, those endpoints become part of the agent's authority boundary even when no credential is visible in the MCP configuration.

## What The Rule Detects

- Explicit cloud metadata addresses in server arguments, URLs, environment values, or nested configuration.
- Metadata hostnames such as `metadata.google.internal`.
- Common metadata paths such as `/latest/meta-data`, `/computeMetadata/v1`, `/metadata/instance`, and `/opc/v2/instance`.
- Wildcard network allowlists in keys such as `allowedHosts`, `egressAllowlist`, `networkAllowlist`, `urlAllowlist`, or `allowedDomains`.

## Risky Example

```json
{
  "mcpServers": {
    "web-fetcher": {
      "command": "node",
      "args": ["fetch-server.js", "--allowed-host", "169.254.169.254"],
      "egressAllowlist": "*"
    }
  }
}
```

This configuration allows a network-capable MCP server to reach the cloud metadata address directly and also declares wildcard egress. If the tool accepts user or retrieved-document URLs, an indirect prompt-injection path can turn into a credential exposure path.

## Safer Pattern

```json
{
  "mcpServers": {
    "docs-fetcher": {
      "owner": "security-engineering",
      "riskOwner": "ai-platform-owner",
      "command": "node",
      "args": ["fetch-server.js"],
      "allowedHosts": ["docs.example.com", "api.example.com"],
      "metadataDenylist": ["169.254.169.254", "metadata.google.internal"]
    }
  }
}
```

Use explicit host allowlists and deny cloud metadata endpoints at both the tool configuration and network layer. The runtime should treat retrieved URLs, model-generated URLs, and user-provided URLs as untrusted until normalized and policy-checked.

## Review Checklist

| Question | Expected Control |
| --- | --- |
| Can the tool request arbitrary URLs? | Require an explicit allowlist and scheme restriction. |
| Can the tool reach `169.254.169.254` or metadata hostnames? | Block cloud metadata endpoints at tool and network layers. |
| Does the agent run with ambient cloud credentials? | Prefer brokered, short-lived, task-bound credentials. |
| Are network scope changes reviewed? | Record owner approval and re-run the MCP audit in CI. |
| Are fetches logged safely? | Log normalized host, scheme, path class, policy decision, and response size without leaking tokens. |

## Response Guidance

If this rule fires, treat it as a high-priority configuration issue before enabling the server in an environment with cloud credentials. Remove wildcard egress, deny metadata endpoints, rotate any credentials that may have been exposed during testing, and capture the remediation in the agent change-control record.
