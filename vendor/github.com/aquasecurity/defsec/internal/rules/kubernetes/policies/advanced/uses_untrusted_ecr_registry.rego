package builtin.kubernetes.KSV035

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

default failTrustedECRRegistry = false

__rego_metadata__ := {
	"id": "KSV035",
	"avd_id": "AVD-KSV-0035",
	"title": "All container images must start with an ECR domain",
	"short_code": "no-untrusted-ecr-domain",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "Container images from non-ECR registries should be forbidden.",
	"recommended_actions": "Container image should be used from Amazon container Registry",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# list of trusted ECR registries
trusted_ecr_registries = [
	"ecr.us-east-2.amazonaws.com",
	"ecr.us-east-1.amazonaws.com",
	"ecr.us-west-1.amazonaws.com",
	"ecr.us-west-2.amazonaws.com",
	"ecr.af-south-1.amazonaws.com",
	"ecr.ap-east-1.amazonaws.com",
	"ecr.ap-south-1.amazonaws.com",
	"ecr.ap-northeast-2.amazonaws.com",
	"ecr.ap-southeast-1.amazonaws.com",
	"ecr.ap-southeast-2.amazonaws.com",
	"ecr.ap-northeast-1.amazonaws.com",
	"ecr.ca-central-1.amazonaws.com",
	"ecr.cn-north-1.amazonaws.com.cn",
	"ecr.cn-northwest-1.amazonaws.com.cn",
	"ecr.eu-central-1.amazonaws.com",
	"ecr.eu-west-1.amazonaws.com",
	"ecr.eu-west-2.amazonaws.com",
	"ecr.eu-south-1.amazonaws.com",
	"ecr.eu-west-3.amazonaws.com",
	"ecr.eu-north-1.amazonaws.com",
	"ecr.me-south-1.amazonaws.com",
	"ecr.sa-east-1.amazonaws.com",
	"ecr.us-gov-east-1.amazonaws.com",
	"ecr.us-gov-west-1.amazonaws.com",
]

# getContainersWithTrustedECRRegistry returns a list of containers
# with image from a trusted ECR registry
getContainersWithTrustedECRRegistry[name] {
	container := kubernetes.containers[_]
	image := container.image

	# get image registry/repo parts
	image_parts := split(image, "/")

	# images with only one part do not specify a registry
	count(image_parts) > 1
	registry = image_parts[0]
	trusted := trusted_ecr_registries[_]
	endswith(registry, trusted)
	name := container.name
}

# getContainersWithUntrustedECRRegistry returns a list of containers
# with image from an untrusted ECR registry
getContainersWithUntrustedECRRegistry[container] {
	container := kubernetes.containers[_]
	not getContainersWithTrustedECRRegistry[container.name]
}

deny[res] {
	container := getContainersWithUntrustedECRRegistry[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should restrict images to own ECR repository. See the full ECR list here: https://docs.aws.amazon.com/general/latest/gr/ecr.html", [container.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, container)
}
