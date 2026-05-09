# Package Registry Credential Context

Package registry credentials are software supply-chain authority. An MCP server that receives npm, PyPI, NuGet, Maven, Gradle, Cargo, RubyGems, Composer, or GitHub Packages credentials can often install private dependencies, read proprietary artifacts, or publish packages under a trusted namespace.

`MCP-032` flags package-registry credential context exposed through MCP server definitions, including:

- package manager token environment variables such as `NPM_TOKEN`, `NODE_AUTH_TOKEN`, `TWINE_PASSWORD`, `PIP_INDEX_URL`, `NUGET_API_KEY`, and `CARGO_REGISTRY_TOKEN`,
- user-level config files such as `.npmrc`, `.pypirc`, `pip.conf`, `NuGet.Config`, `.m2/settings.xml`, `gradle.properties`, `.cargo/credentials`, `.gem/credentials`, and Composer `auth.json`,
- registry URLs with embedded userinfo credentials.

## Why This Matters

Package credentials often bridge development and production systems. If they are available to an agent-accessible MCP server, prompt injection or tool misuse can become a dependency-confusion, package-publishing, artifact-exfiltration, or private-source disclosure incident.

## Safer Pattern

Use isolated build or dependency-read services:

1. Keep user-level package manager config files outside MCP server mounts and command arguments.
2. Use read-only install tokens for dependency lookup and separate publish tokens for release workflows.
3. Keep publish tokens in an approval-gated release system rather than an interactive agent tool.
4. Prefer short-lived tokens and repository-scoped package credentials.
5. Log dependency operations with package name, registry, version, token class, approver, and build reference.

## Review Questions

- Does the MCP server inherit package manager config from a developer workstation?
- Can the token publish, delete, yank, or overwrite trusted packages?
- Are private registries or GitHub Packages exposed to broad tools rather than a dedicated dependency service?
- Is release publishing behind explicit human approval and source-integrity checks?
- Are read-only dependency lookup and high-impact package publishing separated?
