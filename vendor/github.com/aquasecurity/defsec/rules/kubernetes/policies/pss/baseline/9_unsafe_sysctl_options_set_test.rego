package appshield.kubernetes.KSV026

test_sysctls_restricted_property_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sysctls"},
		"spec": {
			"securityContext": {"sysctls": [
				{
					"name": "net.core.somaxconn",
					"value": "1024",
				},
				{
					"name": "kernel.msgmax",
					"value": "65536",
				},
			]},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 1
	r[_].msg == "Pod 'hello-sysctls' should set 'securityContext.sysctl' to the allowed values"
}

test_sysctls_not_restricted_property_mixed_with_restriced_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sysctls"},
		"spec": {
			"securityContext": {"sysctls": [
				{
					"name": "kernel.shm_rmid_forced",
					"value": "0",
				},
				{
					"name": "net.core.somaxconn",
					"value": "1024",
				},
				{
					"name": "kernel.msgmax",
					"value": "65536",
				},
			]},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 1
	r[_].msg == "Pod 'hello-sysctls' should set 'securityContext.sysctl' to the allowed values"
}

test_sysctls_not_restricted_property_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sysctls"},
		"spec": {
			"securityContext": {"sysctls": [{
				"name": "kernel.shm_rmid_forced",
				"value": "0",
			}]},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 0
}

test_sysctls_is_undefined_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-sysctls"},
		"spec": {
			"securityContext": {},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 0
}
