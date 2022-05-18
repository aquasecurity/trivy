package builtin.kubernetes.KSV006

exception[rules] {
	input.metadata.labels.mount == "docker.sock"
	rules := [""]
}
