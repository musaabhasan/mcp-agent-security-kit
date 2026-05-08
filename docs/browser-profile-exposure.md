# Browser Profile Exposure Detection

Rule `MCP-022` flags MCP browser-tool arguments that expose an existing browser profile, cookie database, exported session file, or automation storage-state file. Browser profiles often contain active cookies, saved sessions, extension state, sync metadata, identity hints, and access to sensitive web applications. Handing that state to an agent-accessible browser tool can silently expand the agent's authority beyond the approved task.

## What Is Flagged

The auditor reviews command arguments for:

- Chrome, Chromium, Edge, Brave, or Firefox profile directories
- Windows profile paths such as `AppData\Local\Google\Chrome\User Data`
- macOS profile paths such as `Library/Application Support/Google/Chrome`
- Linux profile paths such as `.config/google-chrome`, `.config/chromium`, and `.mozilla/firefox`
- browser cookie stores such as `Cookies`, `cookies.sqlite`, `logins.json`, and `key4.db`
- automation options such as `--user-data-dir`, `--browser-profile`, `--cookie-file`, `--cookies`, `--storage-state`, and `--auth-state`

Placeholder references such as `${MCP_BROWSER_STORAGE_STATE}` are not flagged because they can point to a controlled runtime secret or isolated automation state.

## Risk Example

```json
{
  "mcpServers": {
    "browser-tools": {
      "command": "node",
      "args": [
        "browser-server.js",
        "--user-data-dir",
        "C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\User Data",
        "--cookie-file=./cookies.json"
      ]
    }
  }
}
```

This configuration can let the MCP browser tool inherit a real user's authenticated web sessions.

## Safer Pattern

```json
{
  "mcpServers": {
    "browser-tools": {
      "owner": "platform",
      "riskOwner": "security",
      "command": "node",
      "args": [
        "browser-server.js",
        "--user-data-dir",
        "./tmp/isolated-mcp-browser-profile",
        "--storage-state",
        "${MCP_BROWSER_STORAGE_STATE}"
      ]
    }
  }
}
```

## Recommended Controls

| Risk | Control |
| --- | --- |
| Agent inherits a user's authenticated web sessions | Use a fresh isolated browser profile for each approved task or environment |
| Browser tool can access email, admin consoles, LMS, cloud, or financial systems | Use a dedicated low-privilege test account and explicit domain allowlist |
| Cookie or storage-state file is exported into the project | Keep session state outside the repository and rotate it after use |
| Agent can retain cross-task browser state | Delete the profile after each run or use short-lived ephemeral containers |
| Browser action cannot be attributed | Log URL, domain, action type, approval decision, and profile/session identifier hash |

Browser automation can be useful for testing and operations, but the browser profile is part of the authority boundary. Treat existing profiles, cookies, and storage-state files like credentials.
