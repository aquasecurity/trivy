package builtin.kubernetes.KSV005

test_cap_without_sys_admin_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sys-admin-capabilities"},
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

test_cap_add_sys_admin_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sys-admin-capabilities"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}},
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-sys-admin-capabilities' should not include 'SYS_ADMIN' in 'securityContext.capabilities.add'"
}
