# MCP Agent Security Control Matrix

| Control Area | Control | Evidence |
| --- | --- | --- |
| Inventory | Maintain an inventory of MCP servers, owners, risk owners, data access, and environments | MCP server register |
| Identity | Use distinct identities for users, agents, service accounts, and tools | IAM design, token scope review |
| Authentication | Require authentication for remote MCP servers | Server config, gateway policy, token validation |
| Authorization | Map each tool to approved actions, data classes, and user groups | Tool permission matrix |
| Least privilege | Grant read-only and narrow path access by default | Config review, access test |
| Secrets | Store tokens in a secret manager or protected local environment | Secret references, vault policy |
| Package integrity | Pin MCP package versions and container images, preferably with immutable digests, and review server updates | Lock files, image digests, release review notes |
| Browser isolation | Use isolated browser profiles and avoid exposing DevTools or CDP sessions to agents | Browser config, MCP-025 scan results, approval record |
| Kubernetes workload identity | Disable unnecessary service account token mounts and broker cluster actions through narrow RBAC | Pod spec, RBAC review, MCP-026 scan results |
| SSH and Git authority | Avoid exposing SSH agent sockets to MCP servers and broker Git or deployment operations through scoped credentials | MCP-027 scan results, deploy key inventory, approval logs |
| Source-control credentials | Keep Git credential helpers, askpass helpers, and user-level credential files out of MCP server environments | MCP-028 scan results, scoped token inventory, source-control approval logs |
| Container runtime authority | Keep Podman, containerd, CRI-O, cri-dockerd, and BuildKit sockets out of direct MCP server reach | MCP-029 scan results, broker design, build/deploy approval logs |
| Cloud operation authority | Keep AWS, Google Cloud, Azure, and OCI CLI profiles, credential files, and config directories out of direct MCP server reach | MCP-030 scan results, cloud IAM review, broker approval logs |
| Database access authority | Keep database passwords, DSNs with embedded credentials, option files, and profile directories out of direct MCP server reach | MCP-031 scan results, database grant review, query broker audit logs |
| Package supply-chain authority | Keep package manager tokens, registry config files, and publish credentials out of direct MCP server reach | MCP-032 scan results, registry token inventory, release approval logs |
| Prompt injection | Label untrusted content and inspect tool outputs before reuse | Test records, blocked examples |
| Human approval | Require approval for high-impact, external, privileged, or irreversible actions | Approval logs |
| Monitoring | Log prompts, tool arguments, tool outputs, denials, approvals, and downstream actions | SIEM queries, trace samples |
| Rate limiting | Limit tool-call frequency and expensive workflows | Gateway policy, runtime config |
| Isolation | Run tools in restricted environments with narrow filesystem and network access | Sandbox config |
| Change control | Review MCP config changes before production rollout | Pull requests, change records |
| Incident response | Define containment steps for tool misuse and token exposure | Playbooks, tabletop records |

## Minimum Production Gate

Before production use, every MCP-enabled agent should have:

- named owner and risk owner,
- approved use case and data classification,
- tool inventory,
- authentication and authorization design,
- secret handling review,
- prompt injection test record,
- logging and retention decision,
- rollback and incident response plan.
