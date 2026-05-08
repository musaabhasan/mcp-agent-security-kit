# Git Credential Helper Exposure

Git credential helpers store or broker authentication for Git remotes. They are convenient for developers, but they become an authority boundary when an MCP server can reach the helper, `.gitconfig`, `.git-credentials`, or an askpass helper.

If an agent-accessible MCP server can call Git and has access to credential helpers, a prompt-injected workflow may be able to fetch, push, open pull requests, tag releases, or interact with private repositories using credentials that were not intended for the agent.

## What MCP-028 Flags

`MCP-028` reports high-severity findings when MCP configuration exposes:

- `GIT_ASKPASS`,
- `GIT_CONFIG_GLOBAL` or `GIT_CONFIG_SYSTEM`,
- `credential.helper=store`, `cache`, `manager`, `manager-core`, `osxkeychain`, `wincred`, `libsecret`, or shell helpers,
- `git-credential-*` helper commands,
- `.gitconfig`,
- `.git-credentials`,
- `.config/git/credentials`.

## Why This Matters

Git credentials often carry broader authority than a single read operation. A local helper may authenticate to personal, institutional, or deployment repositories. Exposing it to an MCP server can collapse the intended separation between a read-only assistant and a tool that can mutate source code, release artifacts, infrastructure-as-code, or documentation.

## Safer Patterns

- Do not mount user-level `.gitconfig` or `.git-credentials` into MCP containers.
- Avoid passing `GIT_ASKPASS` or global Git credential configuration into MCP server environments.
- Use repository-scoped, short-lived tokens for the specific workflow.
- Prefer read-only deploy keys for documentation or knowledge-base indexing.
- Route write, push, tag, merge, and release actions through a broker with policy checks and human approval.
- Log all Git operations that originate from agent-accessible tools.

## Review Questions

- Does the MCP server need Git write access, or only read-only repository content?
- Which repositories can the credential helper access?
- Can the MCP server execute `git push`, `git tag`, `gh pr merge`, release, or deployment commands?
- Is Git write access separated from normal chat or retrieval workflows?
- Are approvals and audit logs enforced for source-control changes?
