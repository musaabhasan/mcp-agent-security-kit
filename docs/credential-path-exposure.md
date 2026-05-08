# Credential Path Exposure Detection

Rule `MCP-020` flags MCP server arguments that expose local credential-bearing paths to agent-accessible tools. These paths may look narrow compared with granting `/` or `C:\`, but they can still give an agent access to keys, cloud sessions, package registry tokens, cluster credentials, or source-control credentials.

## Paths Reviewed

The auditor flags common credential locations and files, including:

- `.ssh`
- `.aws`
- `.azure`
- `.kube`
- `.docker`
- `.gnupg`
- `.config/gcloud`
- `.npmrc`
- `.pypirc`
- `.netrc`
- `.git-credentials`
- private key filenames such as `id_rsa`, `id_ed25519`, `id_ecdsa`, and `id_dsa`

## Risk Example

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem@1.0.0",
        "C:\\Users\\alice\\.ssh",
        "~/.aws",
        "/home/alice/.kube/config"
      ]
    }
  }
}
```

This configuration does not grant full home-directory access, but it still exposes high-value credentials.

## Safer Pattern

```json
{
  "mcpServers": {
    "docs-reader": {
      "owner": "platform",
      "riskOwner": "security",
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem@1.0.0",
        "./docs",
        "--read-only"
      ]
    }
  }
}
```

## Recommended Controls

| Risk | Control |
| --- | --- |
| SSH or Git credentials exposed | Remove the mount and use a brokered Git operation with scoped deploy keys |
| Cloud CLI config exposed | Use workload identity, short-lived credentials, or a narrow service broker |
| Kubernetes config exposed | Replace direct kubeconfig access with a constrained deployment API |
| Package registry tokens exposed | Use ephemeral install credentials or read-only package mirrors |
| Private key file exposed | Rotate the key and investigate whether the agent could read it |

Credential paths should not be part of routine MCP filesystem access. If an agent needs to perform an action that depends on credentials, prefer a purpose-built tool that enforces scope, logs the action, and never returns raw credential material to the model.
