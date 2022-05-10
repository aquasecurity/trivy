package builtin.kubernetes.KSV024

test_host_ports_defined_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-host-ports"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"ports": [{"hostPort": 8080}],
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-host-ports' should not set host ports, 'ports[*].hostPort'"
}

test_no_host_ports_defined_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-host-ports"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"ports": [{"containerPort": 80}],
		}]},
	}

	count(r) == 0
}
