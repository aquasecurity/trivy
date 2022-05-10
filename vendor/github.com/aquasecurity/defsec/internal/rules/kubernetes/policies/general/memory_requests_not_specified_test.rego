package builtin.kubernetes.KSV016

test_memory_requests_not_specified_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-memory-requests"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-memory-requests' should set 'resources.requests.memory'"
}

test_memory_requests_specified_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-cpu-limit"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"resources": {"requests": {"memory": "64Mi"}},
		}]},
	}

	count(r) == 0
}
