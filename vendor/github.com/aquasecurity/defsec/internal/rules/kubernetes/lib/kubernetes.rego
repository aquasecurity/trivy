package lib.kubernetes

default is_gatekeeper = false

is_gatekeeper {
	has_field(input, "review")
	has_field(input.review, "object")
}

object = input {
	not is_gatekeeper
}

object = input.review.object {
	is_gatekeeper
}

format(msg) = gatekeeper_format {
	is_gatekeeper
	gatekeeper_format = {"msg": msg}
}

format(msg) = msg {
	not is_gatekeeper
}

name = object.metadata.name

default namespace = "default"

namespace = object.metadata.namespace

#annotations = object.metadata.annotations

kind = object.kind

is_pod {
	kind = "Pod"
}

is_cronjob {
	kind = "CronJob"
}

default is_controller = false

is_controller {
	kind = "Deployment"
}

is_controller {
	kind = "StatefulSet"
}

is_controller {
	kind = "DaemonSet"
}

is_controller {
	kind = "ReplicaSet"
}

is_controller {
	kind = "ReplicationController"
}

is_controller {
	kind = "Job"
}

split_image(image) = [image, "latest"] {
	not contains(image, ":")
}

split_image(image) = [image_name, tag] {
	[image_name, tag] = split(image, ":")
}

pod_containers(pod) = all_containers {
	keys = {"containers", "initContainers"}
	all_containers = [c | keys[k]; c = pod.spec[k][_]]
}

containers[container] {
	pods[pod]
	all_containers = pod_containers(pod)
	container = all_containers[_]
}

containers[container] {
	all_containers = pod_containers(object)
	container = all_containers[_]
}

pods[pod] {
	is_pod
	pod = object
}

pods[pod] {
	is_controller
	pod = object.spec.template
}

pods[pod] {
	is_cronjob
	pod = object.spec.jobTemplate.spec.template
}

volumes[volume] {
	pods[pod]
	volume = pod.spec.volumes[_]
}

dropped_capability(container, cap) {
	container.securityContext.capabilities.drop[_] == cap
}

added_capability(container, cap) {
	container.securityContext.capabilities.add[_] == cap
}

has_field(obj, field) {
	obj[field]
}

no_read_only_filesystem(c) {
	not has_field(c, "securityContext")
}

no_read_only_filesystem(c) {
	has_field(c, "securityContext")
	not has_field(c.securityContext, "readOnlyRootFilesystem")
}

priviledge_escalation_allowed(c) {
	not has_field(c, "securityContext")
}

priviledge_escalation_allowed(c) {
	has_field(c, "securityContext")
	has_field(c.securityContext, "allowPrivilegeEscalation")
}

annotations[annotation] {
	pods[pod]
	annotation = pod.metadata.annotations
}

host_ipcs[host_ipc] {
	pods[pod]
	host_ipc = pod.spec.hostIPC
}

host_networks[host_network] {
	pods[pod]
	host_network = pod.spec.hostNetwork
}

host_pids[host_pid] {
	pods[pod]
	host_pid = pod.spec.hostPID
}

host_aliases[host_alias] {
	pods[pod]
	host_alias = pod.spec
}
