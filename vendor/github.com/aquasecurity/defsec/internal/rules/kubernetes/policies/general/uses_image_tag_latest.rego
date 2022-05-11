package builtin.kubernetes.KSV013

import data.lib.kubernetes
import data.lib.result

default checkUsingLatestTag = false

__rego_metadata__ := {
	"id": "KSV013",
	"avd_id": "AVD-KSV-0013",
	"title": "Image tag ':latest' used",
	"short_code": "use-specific-tags",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "It is best to avoid using the ':latest' image tag when deploying containers in production. Doing so makes it hard to track which version of the image is running, and hard to roll back the version.",
	"recommended_actions": "Use a specific container image tag that is not 'latest'.",
	"url": "https://kubernetes.io/docs/concepts/configuration/overview/#container-images",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getTaggedContainers returns the names of all containers which
# have tagged images.
getTaggedContainers[container] {
	# If the image defines a digest value, we don't care about the tag
	container := kubernetes.containers[_]
	digest := split(container.image, "@")[1]
}

getTaggedContainers[container] {
	# No digest, look at tag
	container := kubernetes.containers[_]
	tag := split(container.image, ":")[1]
	tag != "latest"
}

# getUntaggedContainers returns the names of all containers which
# have untagged images or images with the latest tag.
getUntaggedContainers[container] {
	container := kubernetes.containers[_]
	not getTaggedContainers[container]
}

deny[res] {
	output := getUntaggedContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should specify an image tag", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}
