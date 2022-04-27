package appshield.kubernetes.KSV013

import data.lib.kubernetes

default checkUsingLatestTag = false

__rego_metadata__ := {
	"id": "KSV013",
	"avd_id": "AVD-KSV-0013",
	"title": "Image tag ':latest' used",
	"short_code": "use-specific-tags",
	"version": "v1.0.0",
	"severity": "LOW",
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
	allContainers := kubernetes.containers[_]
	digest := split(allContainers.image, "@")[1]
	container := allContainers.name
}

getTaggedContainers[container] {
	# No digest, look at tag
	allContainers := kubernetes.containers[_]
	tag := split(allContainers.image, ":")[1]
	tag != "latest"
	container := allContainers.name
}

# getUntaggedContainers returns the names of all containers which
# have untagged images or images with the latest tag.
getUntaggedContainers[container] {
	container := kubernetes.containers[_].name
	not getTaggedContainers[container]
}

# checkUsingLatestTag is true if there is a container whose image tag
# is untagged or uses the latest tag.
checkUsingLatestTag {
	count(getUntaggedContainers) > 0
}

deny[res] {
	checkUsingLatestTag

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should specify an image tag", [getUntaggedContainers[_], kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
