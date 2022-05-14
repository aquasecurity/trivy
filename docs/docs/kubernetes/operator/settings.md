# Settings

Trivy Operator reads configuration settings from ConfigMaps and Secrets.  

The following table lists available settings with their default values.

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

# Example - patch Secret

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


# Example - delete a key

The following `kubectl patch` command deletes the `trivy.httpProxy` key:

```bash
kubectl patch cm trivy-operator-trivy-config -n trivy-operator \
  --type json \
  -p '[{"op": "remove", "path": "/data/trivy.httpProxy"}]'
```

[tolerations]: https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration
