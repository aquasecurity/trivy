package appshield.kubernetes.KSV033

import data.lib.kubernetes
import data.lib.utils

default failTrustedGCRRegistry = false

__rego_metadata__ := {
	"id": "KSV033",
	"avd_id": "AVD-KSV-0033",
	"title": "All container images must start with a GCR domain",
	"short_code": "use-gcr-domain",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "Containers should only use images from trusted GCR registries.",
	"recommended_actions": "Use images from trusted GCR registries.",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# list of trusted GCR registries
trusted_gcr_registries = [
	"gcr.io",
	"us.gcr.io",
	"eu.gcr.io",
	"asia.gcr.io",
]

# getContainersWithTrustedGCRRegistry returns a list of containers
# with image from a trusted gcr registry
getContainersWithTrustedGCRRegistry[name] {
	container := kubernetes.containers[_]
	image := container.image

	# get image registry/repo parts
	image_parts := split(image, "/")

	# images with only one part do not specify a registry
	count(image_parts) > 1
	registry = image_parts[0]
	trusted := trusted_gcr_registries[_]
	endswith(registry, trusted)
	name := container.name
}

# getContainersWithUntrustedGCRRegistry returns a list of containers
# with image from an untrusted gcr registry
getContainersWithUntrustedGCRRegistry[name] {
	name := kubernetes.containers[_].name
	not getContainersWithTrustedGCRRegistry[name]
}

# failTrustedGCRRegistry is true if a container uses an image from an
# untrusted gcr registry
failTrustedGCRRegistry {
	count(getContainersWithUntrustedGCRRegistry) > 0
}

deny[res] {
	failTrustedGCRRegistry

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should restrict container image to your specific registry domain. See the full GCR list here: https://cloud.google.com/container-registry/docs/overview#registries", [getContainersWithUntrustedGCRRegistry[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
