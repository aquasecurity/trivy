# Configuration

You can configure Trivy-Operator to control it's behavior and adapt it to your needs. Aspects of the operator machinery are configured using environment variables on the operator Pod, while aspects of the scanning behavior are controlled by ConfigMaps and Secrets.

# Operator Configuration

| NAME| DEFAULT| DESCRIPTION|
|---|---|---|
| `OPERATOR_NAMESPACE`| N/A| See [Install modes](#install-modes)|
| `OPERATOR_TARGET_NAMESPACES`| N/A| See [Install modes](#install-modes)|
| `OPERATOR_EXCLUDE_NAMESPACES`| N/A| A comma separated list of namespaces (or glob patterns) to be excluded from scanning in all namespaces [Install mode](#install-modes).|
| `OPERATOR_SERVICE_ACCOUNT`| `trivy-operator`| The name of the service account assigned to the operator's pod|
| `OPERATOR_LOG_DEV_MODE`| `false`| The flag to use (or not use) development mode (more human-readable output, extra stack traces and logging information, etc).|
| `OPERATOR_SCAN_JOB_TIMEOUT`| `5m`| The length of time to wait before giving up on a scan job|
| `OPERATOR_CONCURRENT_SCAN_JOBS_LIMIT`| `10`| The maximum number of scan jobs create by the operator|
| `OPERATOR_SCAN_JOB_RETRY_AFTER`| `30s`| The duration to wait before retrying a failed scan job|
| `OPERATOR_BATCH_DELETE_LIMIT`| `10`| The maximum number of config audit reports deleted by the operator when the plugin's config has changed.|
| `OPERATOR_BATCH_DELETE_DELAY`| `10s`| The duration to wait before deleting another batch of config audit reports.|
| `OPERATOR_METRICS_BIND_ADDRESS`| `:8080`| The TCP address to bind to for serving [Prometheus][prometheus] metrics. It can be set to `0` to disable the metrics serving.|
| `OPERATOR_HEALTH_PROBE_BIND_ADDRESS`| `:9090`| The TCP address to bind to for serving health probes, i.e. `/healthz/` and `/readyz/` endpoints.|
| `OPERATOR_VULNERABILITY_SCANNER_ENABLED`| `true`| The flag to enable vulnerability scanner|
| `OPERATOR_CONFIG_AUDIT_SCANNER_ENABLED`| `false`| The flag to enable configuration audit scanner|
| `OPERATOR_CONFIG_AUDIT_SCANNER_SCAN_ONLY_CURRENT_REVISIONS`| `false`| The flag to enable config audit scanner to only scan the current revision of a deployment|
| `OPERATOR_CONFIG_AUDIT_SCANNER_BUILTIN`| `true`| The flag to enable built-in configuration audit scanner|
| `OPERATOR_VULNERABILITY_SCANNER_SCAN_ONLY_CURRENT_REVISIONS`| `false`| The flag to enable vulnerability scanner to only scan the current revision of a deployment|
| `OPERATOR_VULNERABILITY_SCANNER_REPORT_TTL`| `""`| The flag to set how long a vulnerability report should exist. When a old report is deleted a new one will be created by the controller. It can be set to `""` to disabled the TTL for vulnerability scanner. |
| `OPERATOR_LEADER_ELECTION_ENABLED`| `false`| The flag to enable operator replica leader election|
| `OPERATOR_LEADER_ELECTION_ID`| `trivy-operator-lock`| The name of the resource lock for leader election|

The values of the `OPERATOR_NAMESPACE` and `OPERATOR_TARGET_NAMESPACES` determine the install mode, which in turn determines the multitenancy support of the operator.

| MODE| OPERATOR_NAMESPACE | OPERATOR_TARGET_NAMESPACES | DESCRIPTION|
|---|---|---|---|
| OwnNamespace| `operators`| `operators`| The operator can be configured to watch events in the namespace it is deployed in.                             |
| SingleNamespace| `operators`| `foo`| The operator can be configured to watch for events in a single namespace that the operator is not deployed in. |
| MultiNamespace| `operators`| `foo,bar,baz`| The operator can be configured to watch for events in more than one namespace.                                 |
| AllNamespaces| `operators`| (blank string)| The operator can be configured to watch for events in all namespaces.|

## Example - configure namespaces to scan

To change the target namespace from all namespaces to the `default` namespace edit the `trivy-operator` Deployment and change the value of the `OPERATOR_TARGET_NAMESPACES` environment variable from the blank string (`""`) to the `default` value.

# Scanning configuration

| CONFIGMAP KEY| DEFAULT| DESCRIPTION|
|---|---|---|
| `vulnerabilityReports.scanner`| `Trivy`| The name of the plugin that generates vulnerability reports. Either `Trivy` or `Aqua`.|
| `vulnerabilityReports.scanJobsInSameNamespace` | `"false"`| Whether to run vulnerability scan jobs in same namespace of workload. Set `"true"` to enable.|
| `scanJob.tolerations`| N/A| JSON representation of the [tolerations] to be applied to the scanner pods so that they can run on nodes with matching taints. Example: `'[{"key":"key1", "operator":"Equal", "value":"value1", "effect":"NoSchedule"}]'`|
| `scanJob.annotations`| N/A| One-line comma-separated representation of the annotations which the user wants the scanner pods to be annotated with. Example: `foo=bar,env=stage` will annotate the scanner pods with the annotations `foo: bar` and `env: stage` |
| `scanJob.templateLabel`| N/A| One-line comma-separated representation of the template labels which the user wants the scanner pods to be labeled with. Example: `foo=bar,env=stage` will labeled the scanner pods with the labels `foo: bar` and `env: stage`|

## Example - patch ConfigMap

By default Trivy displays vulnerabilities with all severity levels (`UNKNOWN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). To display only `HIGH` and `CRITICAL` vulnerabilities by patching the `trivy.severity` value in the `trivy-operator-trivy-config` ConfigMap:

```bash
kubectl patch cm trivy-operator-trivy-config -n trivy-operator \
  --type merge \
  -p "$(cat <<EOF
{
  "data": {
    "trivy.severity": "HIGH,CRITICAL"
  }
}
EOF
)"
```

## Example - patch Secret

To set the GitHub token used by Trivy scanner add the `trivy.githubToken` value to the `trivy-operator-trivy-config` Secret:

```bash
kubectl patch secret trivy-operator-trivy-config -n trivy-operator \
  --type merge \
  -p "$(cat <<EOF
{
  "data": {
    "trivy.githubToken": "$(echo -n <your token> | base64)"
  }
}
EOF
)"
```

## Example - delete a key

The following `kubectl patch` command deletes the `trivy.httpProxy` key:

```bash
kubectl patch cm trivy-operator-trivy-config -n trivy-operator \
  --type json \
  -p '[{"op": "remove", "path": "/data/trivy.httpProxy"}]'
```

[tolerations]: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration


[prometheus]: https://github.com/prometheus
