package builtin.kubernetes.KSV023

test_host_path_specified_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-host-path"},
		"spec": {
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
			"volumes": [{"hostPath": {
				"path": "/sys",
				"type": "",
			}}],
		},
	}

	count(r) == 1
	r[_].msg == "Pod 'hello-host-path' should not set 'spec.template.volumes.hostPath'"
}

test_host_path_not_specified_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-host-path"},
		"spec": {
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
			"volumes": [{"name": "my-vol"}],
		},
	}

	count(r) == 0
}
