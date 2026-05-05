# MCP Agent Launch Checklist

Use this checklist before connecting an AI agent to MCP servers in a real environment.

## 1. Define The Use Case

- Business process:
- Agent owner:
- Risk owner:
- Users:
- Data classes:
- Environments:

## 2. Review Tool Authority

| Tool | Read | Write | External Action | Approval Required | Owner |
| --- | --- | --- | --- | --- | --- |
|  |  |  |  |  |  |

## 3. Validate MCP Configuration

- Run `mcp-agent-audit` on the configuration.
- Remove shell evaluators unless formally approved.
- Pin package-runner dependencies.
- Remove inline secrets.
- Narrow filesystem paths.
- Require TLS and authentication for remote servers.

## 4. Test Prompt Injection Paths

- Direct user prompt injection.
- Malicious retrieved document.
- Malicious webpage or ticket content.
- Tool output that instructs the agent to change objectives.
- Multi-turn goal hijack.

## 5. Define Runtime Controls

- Tool allowlist:
- Argument validation:
- Output inspection:
- Human approval:
- Rate limits:
- Circuit breaker:

## 6. Define Evidence

- Prompt and output logs:
- Tool-call logs:
- Approval logs:
- Denial logs:
- Incident evidence location:
- Retention period:

## 7. Launch Decision

- Approved:
- Approved with conditions:
- Blocked:
- Required remediation:
- Next review date:
