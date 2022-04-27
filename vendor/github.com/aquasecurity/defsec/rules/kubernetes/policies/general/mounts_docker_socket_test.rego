package appshield.kubernetes.KSV006

test_docker_socket_not_mounted_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-docker-socket"},
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

test_docker_socket_mounted_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-docker-socket"},
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
			"volumes": [{
				"name": "test-volume",
				"hostPath": {
					"path": "/var/run/docker.sock",
					"type": "Directory",
				},
			}],
		},
	}

	count(r) == 1
	r[_].msg == "Pod 'hello-docker-socket' should not specify '/var/run/docker.socker' in 'spec.template.volumes.hostPath.path'"
}
