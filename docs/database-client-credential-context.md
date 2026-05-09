# Database Client Credential Context

MCP servers that can query databases often receive the same client configuration used by an engineer on a workstation or by a broad service account. That is a high-risk boundary because the agent does not need to exploit the database client. It only needs access to a configured DSN, password variable, option file, or profile directory to inherit the authority of that database identity.

`MCP-031` flags database client credential context exposed through server definitions, including:

- PostgreSQL password variables and files such as `PGPASSWORD`, `PGPASSFILE`, `.pgpass`, and `.pg_service.conf`.
- MySQL and MariaDB password variables or client option files such as `MYSQL_PWD`, `.my.cnf`, and `.mylogin.cnf`.
- MongoDB, Redis, and SQL Server connection variables that commonly contain embedded credentials.
- DBT profile paths and ODBC configuration files that can resolve credentials indirectly.
- Database DSNs with embedded userinfo, such as `postgresql://user:password@host/db`.

## Why This Matters

Database access is rarely a single permission. A broad client credential can expose regulated records, student data, audit logs, financial tables, vector-store content, prompt logs, model evaluation datasets, or operational secrets. When that credential is placed directly in an MCP server environment, prompt injection and tool-routing mistakes can become unauthorized query capability.

## Safer Pattern

Use a narrow query broker rather than direct client credential exposure:

1. Create read-only database identities per bot, department, or use case.
2. Limit schemas, rows, and columns through database grants, views, row-level security, or stored procedures.
3. Prefer short-lived credentials or workload identity where the platform supports it.
4. Keep raw DSNs, password files, and option files outside MCP server configuration.
5. Route write operations through approved workflows with explicit confirmation and audit logging.
6. Log query purpose, approved tool name, data classification, row count, and reviewer or workflow reference.

## Review Questions

- Does the MCP server receive a reusable database password, DSN, option file, or profile directory?
- Can the configured identity write, export, or enumerate data beyond the agent's task?
- Are regulated or confidential tables protected by row-level or column-level constraints?
- Is query logging sufficient to reconstruct the prompt, tool, data source, and returned record scope?
- Is there a documented owner for credential rotation, failed query review, and incident response?

## Remediation Examples

- Replace `PGPASSWORD` and `DATABASE_URL` in the MCP server definition with a broker endpoint that only accepts approved analytical queries.
- Replace `.my.cnf` and `.dbt/profiles.yml` mounts with a dedicated service account scoped to a read-only view.
- Move privileged database maintenance actions out of the agent toolset and into a change-controlled administrative workflow.
- Add a release gate that fails if a production DSN, database password variable, or database client option file is introduced into an MCP configuration.
