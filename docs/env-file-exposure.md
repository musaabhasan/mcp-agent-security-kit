# Environment File Exposure Detection

Rule `MCP-021` flags MCP server arguments that expose `.env` or secret-bearing env files to an agent-accessible runtime. Environment files often contain API tokens, OAuth secrets, database URLs, SMTP credentials, cloud keys, webhook secrets, or private service endpoints. Passing them into an MCP server gives the agent runtime broader credential visibility than the task usually requires.

## What Is Flagged

The auditor reviews command arguments for:

- direct `.env` paths such as `.env`, `./.env`, and `/app/.env`
- environment-specific files such as `.env.local`, `.env.production`, and `.env.prod`
- secret-bearing env filenames such as `secrets.env`, `credentials.env`, `token.env`, and `production.env`
- env-file options such as `--env-file`, `--envfile`, `--dotenv`, `--dotenv-file`, and `--env-file-path`

Template files such as `.env.example`, `.env.sample`, `.env.template`, `example.env`, and `sample.env` are not flagged.

## Risk Example

```json
{
  "mcpServers": {
    "runtime": {
      "command": "node",
      "args": [
        "server.js",
        "--env-file=.env.production",
        "--dotenv",
        "./secrets.env"
      ]
    }
  }
}
```

This configuration lets the MCP server load a broad credential set even if the task only requires one narrow token.

## Safer Pattern

```json
{
  "mcpServers": {
    "runtime": {
      "owner": "platform",
      "riskOwner": "security",
      "command": "node",
      "args": [
        "server.js"
      ],
      "env": {
        "MCP_SERVICE_TOKEN": "${MCP_SERVICE_TOKEN}"
      }
    }
  }
}
```

## Recommended Controls

| Risk | Control |
| --- | --- |
| Broad credential set loaded by MCP server | Inject only the specific runtime secret required for the approved tool action |
| Production env file reused locally | Create a narrow development credential profile with reduced scope and short expiry |
| Agent can read or echo env file values | Keep secrets outside agent-readable filesystem paths and redact process/environment capture |
| Multiple providers share one env file | Split credentials by provider, task, and privilege boundary |
| Env file accidentally committed | Rotate credentials, remove the file from history where appropriate, and add secret scanning |

Prefer brokered credential flows, scoped environment references, or managed secret stores. An MCP server should receive the minimum credential needed for the current tool boundary, not the full application runtime environment.
