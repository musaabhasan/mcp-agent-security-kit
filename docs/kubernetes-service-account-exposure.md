# Kubernetes Service Account Exposure

Rule `MCP-026` flags MCP servers that expose Kubernetes service account tokens or in-cluster API endpoints to agent-accessible tools. This usually appears through projected token paths such as `/var/run/secrets/kubernetes.io/serviceaccount/token`, Kubernetes API hostnames such as `kubernetes.default.svc`, or pod configuration that enables `automountServiceAccountToken`.

Kubernetes service account tokens can carry real cluster permissions. If an agent can read the token or call the in-cluster API directly, the agent may inherit deployment, secret, pod, log, or namespace access that was granted to the workload rather than intentionally granted to the agent.

## What The Rule Detects

- Projected service account paths under `/var/run/secrets/kubernetes.io/serviceaccount`.
- Alternate projected paths under `/run/secrets/kubernetes.io/serviceaccount`.
- In-cluster API hostnames such as `kubernetes.default.svc` and `kubernetes.default.svc.cluster.local`.
- Configuration keys such as `kubernetesApiUrl`, `kubeApiServer`, `serviceAccountTokenPath`, and `kubernetesServiceHost`.
- `automountServiceAccountToken: true` in nested pod or runtime configuration.

## Risky Example

```json
{
  "mcpServers": {
    "cluster-admin": {
      "command": "node",
      "args": [
        "k8s-server.js",
        "/var/run/secrets/kubernetes.io/serviceaccount/token"
      ],
      "kubernetesApiUrl": "https://kubernetes.default.svc"
    }
  }
}
```

This configuration gives an agent-accessible tool a direct path to the pod service account token and the in-cluster Kubernetes API. If the service account is over-privileged, prompt injection or tool misuse can become cluster misuse.

## Safer Pattern

```json
{
  "mcpServers": {
    "k8s-reader": {
      "owner": "platform-security",
      "riskOwner": "cluster-owner",
      "command": "node",
      "args": ["k8s-reader.js", "--namespace", "training"],
      "automountServiceAccountToken": false,
      "allowedActions": ["get_pod_status", "list_events"],
      "approvalRequiredFor": ["delete_pod", "create_secret", "patch_deployment"]
    }
  }
}
```

Prefer a brokered Kubernetes gateway that receives narrow, task-scoped requests and enforces namespace, verb, resource, and approval policy. Disable automatic service account token mounting for agent workloads unless the workload explicitly requires it and the service account is tightly scoped.

## Review Checklist

| Question | Expected Control |
| --- | --- |
| Can the MCP server read a projected service account token? | Disable token mount or remove token path access. |
| Can the tool call the in-cluster Kubernetes API? | Broker calls through a policy gateway with namespace and verb restrictions. |
| What verbs and resources can the service account access? | Review RBAC for secrets, pods, deployments, jobs, logs, exec, and patch permissions. |
| Are high-impact actions possible? | Require approval for delete, patch, exec, secret, deployment, and namespace-changing actions. |
| Are Kubernetes actions auditable? | Record agent identity, principal, namespace, verb, resource, policy decision, and request ID. |

## Response Guidance

If this rule fires, treat it as a high-priority identity and privilege boundary issue. Remove token path exposure, disable automatic token mounting where possible, review the service account RBAC, rotate exposed tokens if necessary, and route Kubernetes actions through an auditable gateway with explicit allowlists.
