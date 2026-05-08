# Container Runtime Socket Exposure

Container runtime sockets are high-authority control planes. If an MCP server can access a Podman, containerd, CRI-O, cri-dockerd, or BuildKit socket, an agent may be able to start containers, mount host paths, build images, pull unreviewed artifacts, or influence deployment workflows outside the intended tool boundary.

## What The Rule Detects

`MCP-029` flags container runtime socket references in MCP server configuration, including:

- `/run/podman/podman.sock`
- `/run/user/<uid>/podman/podman.sock`
- `/run/containerd/containerd.sock`
- `/run/crio/crio.sock`
- `/run/cri-dockerd.sock`
- `/run/buildkit/buildkitd.sock`
- matching `unix://` socket URLs
- Windows named pipe patterns for Podman, containerd, and BuildKit
- explicit config keys such as `containerRuntimeSocket`, `podmanSocket`, `containerdSocket`, `crioSocket`, and `buildkitSocket`

Docker socket exposure remains covered by `MCP-016`; this rule covers adjacent runtime sockets that create similar agent authority.

## Why It Matters

Runtime socket access can turn a narrow MCP tool into a host, build, or cluster control path. Common failure modes include:

- mounting sensitive host directories into a new container,
- building or running unreviewed images,
- using build secrets outside approved workflows,
- bypassing intended CI/CD approvals,
- writing artifacts to registries or deployment paths,
- reading files from host-mounted paths through container execution.

## Safer Patterns

- Use a brokered build or deployment API instead of exposing runtime sockets directly.
- Scope allowed operations to approved projects, images, registries, and environments.
- Require explicit human approval for build, push, deploy, and host-mount operations.
- Keep runtime socket access out of general-purpose agent tools.
- Run build services with dedicated identities, short-lived credentials, and audit logs.
- Record socket access decisions in the MCP server owner review.

## Review Questions

| Question | Expected Evidence |
| --- | --- |
| Does the MCP server need container runtime control, or only build status/read access? | Use-case approval and tool permission matrix |
| Can the action be brokered through a narrower API? | Broker design or service boundary diagram |
| Are host mounts, privileged containers, and registry writes blocked by policy? | Runtime policy, admission policy, or wrapper tests |
| Are build and deploy operations tied to approval records? | Approval logs and deployment evidence |
| Are socket-access attempts logged and alerted? | SIEM query, runtime log sample, and alert rule |
