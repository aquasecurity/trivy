# Kubernetes REGO Filter Policies

This directory contains example REGO policies for filtering Kubernetes resources during Trivy scans.

## Feature Overview

The Kubernetes REGO filtering feature allows you to skip scanning specific Kubernetes resources based on custom REGO rules. This is useful for:

- Excluding system resources that are not relevant to security scans
- Filtering out test/development resources in multi-environment clusters
- Skipping resources with zero replicas (addressed issue #8078)
- Applying custom business logic for resource selection

## Usage

### Basic Usage

```bash
# Filter out deployments with zero replicas
trivy k8s --k8s-filter-policy=deployment-zero-replicas.rego cluster

# Filter out system resources
trivy k8s --k8s-filter-policy=system-resources.rego cluster

# Use multiple data files with a policy
trivy k8s --k8s-filter-policy=custom.rego --k8s-filter-data=config.rego cluster
```

### Multiple Policies

You can combine multiple policies by creating a comprehensive policy file that imports or includes multiple rules.

## Policy Structure

All Kubernetes filter policies must:

1. Use the package `trivy.kubernetes`
2. Define rules under the `ignore` decision
3. Return a boolean value (true to ignore the resource)

### Input Format

The input to your REGO policy will be a Kubernetes artifact with the following structure:

```json
{
  "kind": "Deployment",
  "namespace": "default", 
  "name": "my-app",
  "labels": {
    "app": "my-app",
    "version": "v1.0.0"
  },
  "annotations": {
    "deployment.kubernetes.io/revision": "1"
  },
  "spec": {
    "replicas": 3,
    "template": {
      "spec": {
        "containers": [...]
      }
    }
  }
}
```

## Example Policies

### 1. deployment-zero-replicas.rego
Filters out Deployments with zero replicas (addresses issue #8078).

### 2. system-resources.rego  
Excludes system-level resources like those in kube-system namespace.

### 3. environment-based.rego
Filters resources based on environment labels and annotations.

### 4. workload-specific.rego
Advanced filtering based on workload specifications and states.

## Writing Custom Policies

### Basic Filter
```rego
package trivy.kubernetes

ignore {
    input.namespace == "test"
}
```

### Label-based Filter
```rego
package trivy.kubernetes

ignore {
    input.labels["environment"] == "dev"
}
```

### Spec-based Filter
```rego
package trivy.kubernetes

ignore {
    input.kind == "Deployment"
    input.spec.replicas == 0
}
```

### Complex Conditions
```rego
package trivy.kubernetes

ignore {
    input.kind in ["Pod", "Deployment"]
    startswith(input.namespace, "temp-")
    input.labels["temporary"] == "true"
}
```

## Testing Policies

You can test your REGO policies using the OPA CLI:

```bash
# Test a policy with sample input
opa eval -d policy.rego -i input.json "data.trivy.kubernetes.ignore"
```

## Integration with CI/CD

These policies can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions step
- name: Scan Kubernetes with filtering
  run: |
    trivy k8s \
      --k8s-filter-policy=.trivy/k8s-filter.rego \
      --format=sarif \
      --output=trivy-k8s.sarif \
      cluster
```

## Troubleshooting

- **Policy not working**: Ensure the package name is exactly `trivy.kubernetes`
- **Syntax errors**: Validate your REGO syntax with `opa fmt` and `opa test`
- **No resources filtered**: Check that your conditions match the actual resource structure
- **Too many resources filtered**: Add debug logging to understand which rules are matching

## Contributing

When contributing new example policies:

1. Include clear comments explaining the use case
2. Add usage examples in the policy file
3. Test the policy with real Kubernetes resources
4. Update this README with the new policy description