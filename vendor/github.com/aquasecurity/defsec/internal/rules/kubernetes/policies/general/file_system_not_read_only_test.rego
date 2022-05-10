package builtin.kubernetes.KSV014

test_read_only_root_file_system_not_set_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-fs-not-readonly"},
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
	r[_].msg == "Container 'hello' of Pod 'hello-fs-not-readonly' should set 'securityContext.readOnlyRootFilesystem' to true"
}

test_read_only_root_file_system_false_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-fs-not-readonly"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"readOnlyRootFilesystem": false},
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-fs-not-readonly' should set 'securityContext.readOnlyRootFilesystem' to true"
}

test_read_only_root_file_system_true_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-fs-not-readonly"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"readOnlyRootFilesystem": true},
		}]},
	}

	count(r) == 0
}
