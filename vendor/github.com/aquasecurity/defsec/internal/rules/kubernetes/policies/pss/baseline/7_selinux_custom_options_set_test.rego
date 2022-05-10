package builtin.kubernetes.KSV025

test_pod_invalid_selinux_type_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-selinux"},
		"spec": {
			"securityContext": {"seLinuxOptions": {"type": "custom"}},
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
	r[_].msg == "Pod 'hello-selinux' uses invalid seLinux type 'custom'"
}

test_container_invalid_selinux_type_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-selinux"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"seLinuxOptions": {"type": "custom"}},
		}]},
	}

	count(r) == 1
	r[_].msg == "Pod 'hello-selinux' uses invalid seLinux type 'custom'"
}

test_empty_selinux_options_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-selinux"},
		"spec": {
			"securityContext": {"seLinuxOptions": {}},
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

test_no_security_context_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-selinux"},
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

test_restricted_key_in_selinux_options_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-selinux"},
		"spec": {
			"securityContext": {"seLinuxOptions": {"type": "container_t", "role": "admin"}},
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
	r[_].msg == "Pod 'hello-selinux' uses restricted properties in seLinuxOptions: ('role')"
}

test_multiple_restricted_keys_in_selinux_options_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-selinux"},
		"spec": {
			"securityContext": {"seLinuxOptions": {"type": "container_t", "role": "admin", "user": "root"}},
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
	r[_].msg == "Pod 'hello-selinux' uses restricted properties in seLinuxOptions: ('role', 'user')"
}

test_containers_have_multiple_restricted_keys_in_selinux_options_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-selinux"},
		"spec": {"containers": [
			{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
				"securityContext": {"seLinuxOptions": {"type": "container_t", "role": "admin", "user": "root"}},
			},
			{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello2",
				"securityContext": {"seLinuxOptions": {"type": "container_t", "role": "admin", "user": "root"}},
			},
		]},
	}

	count(r) == 1
	r[_].msg == "Pod 'hello-selinux' uses restricted properties in seLinuxOptions: ('role', 'user')"
}
