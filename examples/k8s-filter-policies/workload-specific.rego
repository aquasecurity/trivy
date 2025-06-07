# Example REGO policy for workload-specific filtering
# This policy shows advanced filtering based on workload specifications

package trivy.kubernetes

# Filter out suspended CronJobs
ignore {
	input.kind == "CronJob"
	input.spec.suspend == true
}

# Filter out services without selectors (external services)
ignore {
	input.kind == "Service"
	not input.spec.selector
}

# Filter out completed jobs
ignore {
	input.kind == "Job"
	input.spec.completions == input.spec.parallelism
}

# Filter out deployments with very low resource requests (likely test deployments)
ignore {
	input.kind == "Deployment"
	input.spec.template.spec.containers[_].resources.requests.memory == "1Mi"
}

# Filter out StatefulSets with 0 replicas
ignore {
	input.kind == "StatefulSet"
	input.spec.replicas == 0
}

# Usage:
# trivy k8s --k8s-filter-policy=workload-specific.rego cluster