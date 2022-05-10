package builtin.kubernetes.KSV029

test_run_as_group_not_defined_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-run-as-group"},
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

test_run_as_group_set_to_zero_for_pod_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-run-as-group"},
		"spec": {
			"securityContext": {"runAsGroup": 0},
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
	r[_].msg == "Pod 'hello-run-as-group' should set 'spec.securityContext.runAsGroup', 'spec.securityContext.supplementalGroups[*]' and 'spec.securityContext.fsGroup' to integer greater than 0"
}

test_run_as_group_set_to_value_greater_than_10000_for_pod_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-run-as-group"},
		"spec": {
			"securityContext": {"runAsGroup": 10001},
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

test_supplemental_groups_is_defined_for_pod_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-run-as-group"},
		"spec": {
			"securityContext": {"supplementalGroups": {"rule": "RunAsAny"}},
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
	r[_].msg == "Pod 'hello-run-as-group' should set 'spec.securityContext.runAsGroup', 'spec.securityContext.supplementalGroups[*]' and 'spec.securityContext.fsGroup' to integer greater than 0"
}

test_fs_group_is_defined_for_pod_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-run-as-group"},
		"spec": {
			"securityContext": {"fsGroup": {"rule": "RunAsAny"}},
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
	r[_].msg == "Pod 'hello-run-as-group' should set 'spec.securityContext.runAsGroup', 'spec.securityContext.supplementalGroups[*]' and 'spec.securityContext.fsGroup' to integer greater than 0"
}
