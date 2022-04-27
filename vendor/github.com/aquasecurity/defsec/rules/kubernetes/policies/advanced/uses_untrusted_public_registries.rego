package appshield.kubernetes.KSV034

import data.lib.kubernetes
import data.lib.utils

default failPublicRegistry = false

__rego_metadata__ := {
	"id": "KSV034",
	"avd_id": "AVD-KSV-0034",
	"title": "Container images from public registries used",
	"short_code": "no-public-registries",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "Container images must not start with an empty prefix or a defined public registry domain.",
	"recommended_actions": "Use images from private registries.",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# list of untrusted public registries
untrusted_public_registries = [
	"docker.io",
	"ghcr.io",
]

# getContainersWithPublicRegistries returns a list of containers
# with public registry prefixes
getContainersWithPublicRegistries[name] {
	container := kubernetes.containers[_]
	image := container.image
	untrusted := untrusted_public_registries[_]
	startswith(image, untrusted)
	name := container.name
}

# getContainersWithPublicRegistries returns a list of containers
# with image without registry prefix
getContainersWithPublicRegistries[name] {
	container := kubernetes.containers[_]
	image := container.image
	image_parts := split(image, "/") # get image registry/repo parts
	count(image_parts) > 0
	not contains(image_parts[0], ".") # check if first part is a url (assuming we have "." in url)
	name := container.name
}

# failPublicRegistry is true if a container uses an image from an
# untrusted public registry
failPublicRegistry {
	count(getContainersWithPublicRegistries) > 0
}

deny[res] {
	failPublicRegistry

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should restrict container image to use private registries", [getContainersWithPublicRegistries[_], kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
