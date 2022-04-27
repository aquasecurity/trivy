package appshield.kubernetes.KSV202

import data.lib.kubernetes

__rego_metadata__ := {
	"id": "KSV102",
	"avd_id": "AVD-KSV-0102",
	"title": "Tiller Is Deployed",
	"short_code": "no-tiller",
	"version": "v1.0.0",
	"severity": "Critical",
	"type": "Kubernetes Security Check",
	"description": "Check if Helm Tiller component is deployed.",
	"recommended_actions": "Migrate to Helm v3 which no longer has Tiller component",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# Get all containers and check kubernetes metadata for tiller
tillerDeployed[container] {
	currentContainer := kubernetes.containers[_]
	checkMetadata(input.metadata)
	container := currentContainer.name
}

# Get all containers and check each image for tiller
tillerDeployed[container] {
	currentContainer := kubernetes.containers[_]
	contains(currentContainer.image, "tiller")
	container := currentContainer.name
}

# Get all pods and check each metadata for tiller
tillerDeployed[pod] {
	currentPod := kubernetes.pods[_]
	checkMetadata(currentPod.metadata)
	pod := currentPod.metadata.name
}

deny[res] {
	msg := kubernetes.format(sprintf("container '%s' of %s '%s' in '%s' namespace shouldn't have tiller deployed", [tillerDeployed[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

# Check for tiller by resource name
checkMetadata(metadata) {
	contains(metadata.name, "tiller")
}

# Check for tiller by app label
checkMetadata(metadata) {
	metadata.labels.app == "helm"
}

# Check for tiller by name label
checkMetadata(metadata) {
	metadata.labels.name == "tiller"
}
