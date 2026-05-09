# CI/CD Credential Context

CI/CD credentials are deployment authority. An MCP server that receives GitHub Actions, GitLab CI, CircleCI, Buildkite, Jenkins, Azure DevOps, Vercel, Netlify, Drone, or TeamCity tokens can often read artifacts, mint OIDC claims, deploy workloads, modify environments, or trigger release pipelines.

`MCP-033` flags CI/CD credential context exposed through MCP server definitions, including:

- runtime tokens such as `GITHUB_TOKEN`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, `CI_JOB_TOKEN`, and `SYSTEM_ACCESSTOKEN`,
- provider API tokens such as CircleCI, Buildkite, Jenkins, Azure DevOps, Vercel, Netlify, Drone, and TeamCity tokens,
- local CI credential files such as `.config/gh/hosts.yml`, `.circleci/cli.yml`, `.buildkite-agent/token`, and Jenkins credential stores,
- CI provider URLs with embedded credentials.

## Why This Matters

CI/CD credentials can cross the boundary from chat-time tool use into deployment, artifact, and environment control. Prompt injection against an agent-accessible MCP server should not be able to reuse the same credentials that publish packages, deploy infrastructure, mint OIDC tokens, or approve production jobs.

## Safer Pattern

1. Keep CI runtime tokens out of MCP server environments.
2. Broker deployment and pipeline actions through a service that enforces repository, branch, environment, and approver policy.
3. Use short-lived OIDC claims only inside approved jobs, not long-lived interactive tools.
4. Separate read-only pipeline status tools from build, release, and deployment tools.
5. Log deployment intent, target environment, commit SHA, approver, and downstream job URL.

## Review Questions

- Can this MCP server trigger, approve, or modify a build or deployment?
- Does it inherit runtime job tokens from a CI runner or developer workstation?
- Are production environments protected by branch, reviewer, and environment gates?
- Are OIDC tokens minted only inside approved job contexts?
- Are deployment and package-release credentials separated from diagnostic tools?
