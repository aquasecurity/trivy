package builtin.kubernetes.KSV032

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

default failTrustedAzureRegistry = false

__rego_metadata__ := {
	"id": "KSV032",
	"avd_id": "AVD-KSV-0032",
	"title": "All container images must start with the *.azurecr.io domain",
	"short_code": "use-azure-image-prefix",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "Containers should only use images from trusted registries.",
	"recommended_actions": "Use images from trusted Azure registries.",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getContainersWithTrustedAzureRegistry returns a list of containers
# with image from a trusted Azure registry
getContainersWithTrustedAzureRegistry[name] {
	container := kubernetes.containers[_]
	image := container.image

	# get image registry/repo parts
	image_parts := split(image, "/")

	# images with only one part do not specify a registry
	count(image_parts) > 1
	registry = image_parts[0]
	endswith(registry, "azurecr.io")
	name := container.name
}

# getContainersWithUntrustedAzureRegistry returns a list of containers
# with image from an untrusted Azure registry
getContainersWithUntrustedAzureRegistry[container] {
	container := kubernetes.containers[_]
	not getContainersWithTrustedAzureRegistry[container.name]
}

deny[res] {
	container := getContainersWithUntrustedAzureRegistry[_]
	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should restrict container image to your specific registry domain. For Azure any domain ending in 'azurecr.io'", [container.name, lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))
	res := result.new(msg, container)
}
