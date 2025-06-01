# Example REGO policy to filter out system Kubernetes resources
# This policy excludes resources commonly found in system namespaces

package trivy.kubernetes

# Filter out resources in system namespaces
ignore {
	input.namespace in [
		"kube-system", 
		"kube-public", 
		"kube-node-lease",
		"local-path-storage"
	]
}

# Filter out daemon sets (often system-level)
ignore {
	input.kind == "DaemonSet"
}

# Filter out resources with system labels
ignore {
	input.labels["app.kubernetes.io/managed-by"] in ["kubeadm", "kops"]
}

# Usage:
# trivy k8s --k8s-filter-policy=system-resources.rego cluster