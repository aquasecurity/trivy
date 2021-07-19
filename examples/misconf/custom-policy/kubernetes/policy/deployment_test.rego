package user.kubernetes.ID001

test_denied {
	r := deny with input as {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {"name": "test-deny"},
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
		}]}}},
	}

	count(r) == 1
	r[_] == "Found deployment 'test-deny' but deployments are not allowed"
}

test_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "test-allow"},
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

	count(r) == 0
}
