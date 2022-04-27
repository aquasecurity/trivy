package appshield.kubernetes.KSV040

test_use_resource_quota_configure {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "mem-cpu-demo"},
		"spec": {"hard": {
			"requests.cpu": "1",
			"requests.memory": "1Gi",
			"limits.cpu": "2",
			"limits.memory": "2Gi",
		}},
	}

	count(r) == 0
}

test_use_resource_quota_configure_no_hard {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "mem-cpu-demo"},
		"spec": {},
	}

	r[_].msg == "resource quota policy with hard memory and cpu quota per namespace should be configure"
}

test_use_resource_quota_configure_no_request_cpu {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "mem-cpu-demo"},
		"spec": {"hard": {
			"requests.memory": "1Gi",
			"limits.cpu": "2",
			"limits.memory": "2Gi",
		}},
	}

	r[_].msg == "resource quota policy with hard memory and cpu quota per namespace should be configure"
}

test_use_resource_quota_configure_no_request_memory {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "mem-cpu-demo"},
		"spec": {"hard": {
			"requests.cpu": "1",
			"limits.cpu": "2",
			"limits.memory": "2Gi",
		}},
	}

	r[_].msg == "resource quota policy with hard memory and cpu quota per namespace should be configure"
}

test_use_resource_quota_configure_no_limits_cpu {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "mem-cpu-demo"},
		"spec": {"hard": {
			"requests.cpu": "1",
			"requests.memory": "1Gi",
			"limits.memory": "2Gi",
		}},
	}

	r[_].msg == "resource quota policy with hard memory and cpu quota per namespace should be configure"
}

test_use_resource_quota_configure_no_limits_memory {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "ResourceQuota",
		"metadata": {"name": "mem-cpu-demo"},
		"spec": {"hard": {
			"requests.cpu": "1",
			"requests.memory": "1Gi",
			"limits.cpu": "2",
		}},
	}

	r[_].msg == "resource quota policy with hard memory and cpu quota per namespace should be configure"
}
