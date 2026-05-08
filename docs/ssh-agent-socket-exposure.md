# SSH Agent Socket Exposure

SSH agents are convenience tools for signing Git and server-authentication challenges without copying private keys into every process. That convenience becomes a security boundary when an MCP server can reach the agent socket.

If an agent-accessible MCP server receives `SSH_AUTH_SOCK`, `/tmp/ssh-*/agent.*`, `openssh-ssh-agent`, Pageant, or a forwarded OpenSSH named pipe, the MCP workflow may be able to authenticate to Git remotes, internal servers, or deployment hosts using the user's loaded keys.

## What MCP-027 Flags

`MCP-027` reports high-severity findings when an MCP server configuration exposes:

- `SSH_AUTH_SOCK` in environment variables,
- `sshAgentSocket`, `sshAgentSock`, or similar configuration keys,
- Unix agent socket paths such as `/tmp/ssh-AbCdE/agent.12345`,
- Linux keyring socket paths such as `/run/user/1000/keyring/ssh`,
- Windows OpenSSH agent pipes such as `//./pipe/openssh-ssh-agent`,
- Pageant or `npiperelay` agent forwarding references.

## Why This Matters

SSH agent exposure is different from committing a private key, but it can still grant real authority. A compromised or prompt-injected MCP server may request signatures from the agent and use them for Git operations, server logins, repository writes, or deployment actions that were never intended for the AI workflow.

## Safer Patterns

- Avoid passing SSH agent sockets into MCP tools by default.
- Use read-only deploy keys scoped to one repository when Git access is required.
- Prefer short-lived provider tokens with narrow repository, branch, and operation scopes.
- Route write operations through a broker that enforces approval, branch policy, and audit logging.
- Keep Git, deployment, and infrastructure actions behind explicit confirmation and policy checks.
- Log attempted Git and SSH operations as security-relevant tool events.

## Review Questions

- Does this MCP server need Git write access or only read-only repository content?
- Is the exposed SSH identity personal, shared, or production privileged?
- Can the MCP server invoke `git`, `ssh`, deployment tools, or shell commands?
- Are write, merge, deploy, and release actions protected by human approval?
- Is there a separate audit trail for Git operations triggered through the MCP tool?
