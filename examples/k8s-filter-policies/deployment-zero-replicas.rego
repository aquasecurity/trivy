# Example REGO policy to filter out Kubernetes Deployments with zero replicas
# This addresses the specific use case mentioned in issue #8078

package trivy.kubernetes

# Filter out deployments with zero replicas
ignore {
	input.kind == "Deployment"
	input.spec.replicas == 0
}

# Usage:
# trivy k8s --k8s-filter-policy=deployment-zero-replicas.rego cluster