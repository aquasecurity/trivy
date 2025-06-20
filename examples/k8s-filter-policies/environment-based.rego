# Example REGO policy to filter resources based on environment
# This policy demonstrates filtering based on labels and annotations

package trivy.kubernetes

# Filter out test environment resources
ignore {
	input.labels["environment"] in ["test", "staging", "dev"]
}

# Filter out resources marked for skipping
ignore {
	input.annotations["trivy.skip"] == "true"
}

# Filter out temporary/debug resources
ignore {
	startswith(input.name, "debug-")
}

# Filter out canary deployments
ignore {
	input.kind == "Deployment"
	input.labels["deployment-type"] == "canary"
}

# Usage:
# trivy k8s --k8s-filter-policy=environment-based.rego cluster