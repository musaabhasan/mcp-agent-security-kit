# Browser Debugging Interface Exposure

Rule `MCP-025` flags MCP servers that expose browser DevTools, Chrome DevTools Protocol (CDP), or remote debugging interfaces to agent-accessible tools. This usually appears as `--remote-debugging-port`, `--remote-debugging-pipe`, `--remote-allow-origins=*`, `cdpUrl`, `debuggerUrl`, `webSocketDebuggerUrl`, or a `/json/version` endpoint.

Browser debugging interfaces are powerful because they can inspect pages, read DOM state, automate navigation, access authenticated sessions, and interact with applications as the browser user. If an agent can connect to an existing debugging session, the effective authority boundary becomes the browser profile, not the MCP tool description.

## What The Rule Detects

- Browser launch arguments that enable remote debugging ports or pipes.
- Wildcard remote debugging origins.
- CDP or DevTools URLs such as `http://127.0.0.1:9222/json/version`.
- WebSocket debugger URLs such as `ws://127.0.0.1:9222/devtools/browser/...`.
- Nested configuration fields named `cdpUrl`, `debuggerUrl`, `devtoolsUrl`, `browserDebugUrl`, or `webSocketDebuggerUrl`.

## Risky Example

```json
{
  "mcpServers": {
    "browser": {
      "command": "node",
      "args": [
        "browser-server.js",
        "--remote-debugging-port=9222",
        "--remote-allow-origins=*"
      ],
      "cdpUrl": "http://127.0.0.1:9222/json/version"
    }
  }
}
```

This configuration can let an agent attach to a debugging endpoint with broad origin access. If that endpoint is tied to a real user profile, an indirect prompt-injection attack can become authenticated browser automation.

## Safer Pattern

```json
{
  "mcpServers": {
    "browser": {
      "owner": "security-engineering",
      "riskOwner": "ai-platform-owner",
      "command": "node",
      "args": [
        "browser-server.js",
        "--user-data-dir",
        "./tmp/isolated-mcp-browser-profile"
      ],
      "allowedDomains": ["docs.example.com", "training.example.com"],
      "approvalRequiredFor": ["submit_form", "download_file", "external_navigation"]
    }
  }
}
```

Use an isolated browser profile, task-specific account, explicit domain allowlist, and approval gates for form submission, downloads, external navigation, and authenticated application actions. Avoid connecting the agent to an existing user's browser debugging session.

## Review Checklist

| Question | Expected Control |
| --- | --- |
| Does the tool connect to a DevTools or CDP endpoint? | Require isolated browser context and owner approval. |
| Is remote debugging bound to wildcard origins or non-local interfaces? | Remove wildcard origins and keep debugging local-only when unavoidable. |
| Does the endpoint use a real user profile? | Replace with an ephemeral profile and test account. |
| Can the agent submit forms, download files, or navigate to external sites? | Require explicit domain and action allowlists plus approval gates. |
| Are browser actions logged? | Record normalized URL, action type, approval state, browser context ID, and downstream effect. |

## Response Guidance

If this rule fires, treat it as a high-priority authority-boundary issue. Disable remote debugging exposure, rotate any credentials that may have been accessible through the browser profile, move testing to an isolated profile, and document the review in the agent change-control record.
