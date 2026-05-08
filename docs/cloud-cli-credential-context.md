# Cloud CLI Credential Context Exposure

Cloud CLI profiles and credential files are authority boundaries. If an MCP server inherits AWS, Google Cloud, Azure, or OCI CLI context, an agent-accessible tool may gain access to cloud projects, storage, secrets, registries, deployments, logs, or identity operations that were never intended for the assistant.

## What The Rule Detects

`MCP-030` flags cloud CLI credential context in MCP server configuration, including:

- `AWS_PROFILE`, `AWS_DEFAULT_PROFILE`, `AWS_SHARED_CREDENTIALS_FILE`, and `AWS_CONFIG_FILE`
- `GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDSDK_CONFIG`, and `gcloud` configuration paths
- `AZURE_CONFIG_DIR` and `.azure` directory exposure
- OCI CLI config file and profile settings
- mounted `.aws/credentials`, `.aws/config`, `.config/gcloud`, `.azure`, and `.oci/config` paths
- service-account and application-default-credential JSON paths

## Why It Matters

Cloud CLI context can silently expand an MCP server from a narrow tool into a cloud operation path. Common risks include:

- reading buckets, queues, logs, or databases outside the approved project,
- creating or changing infrastructure,
- accessing secret stores or container registries,
- deploying workloads with inherited developer or runner privileges,
- bypassing cloud approval and change-control workflows,
- leaking service-account JSON or profile names into logs and traces.

## Safer Patterns

- Use scoped workload identity rather than user-level CLI profiles.
- Issue short-lived tokens for one approved action at a time.
- Broker cloud operations through a gateway that enforces allowlists, approval, and audit logging.
- Keep `.aws`, `.azure`, `.config/gcloud`, and `.oci` directories out of MCP mounts.
- Separate read-only diagnostic tools from write-capable cloud automation tools.
- Record cloud project, account, role, and allowed actions in the MCP server owner review.

## Review Questions

| Question | Expected Evidence |
| --- | --- |
| Which cloud account, project, subscription, or tenancy can the MCP server reach? | Cloud access review |
| Is the credential scoped to the exact action needed by the tool? | IAM policy or workload identity binding |
| Are cloud write, deploy, delete, and secret-read operations behind approval? | Approval policy and audit logs |
| Are user-level CLI profiles excluded from container mounts and environment variables? | MCP-030 scan results |
| Are cloud operations logged with prompt, tool, user, and approval context? | SIEM query and trace sample |
