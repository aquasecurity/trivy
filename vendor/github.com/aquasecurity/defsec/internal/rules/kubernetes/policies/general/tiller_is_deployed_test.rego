package builtin.kubernetes.KSV102

test_tiller_deployed_by_image {
	res := deny with input as {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {"name": "mongo-deployment"},
		"spec": {"template": {"spec": {
			"containers": [{
				"name": "carts-db",
				"image": "tiller",
				"securityContext": {
					"runAsNonRoot": true,
					"allowPrivilegeEscalation": true,
				},
			}],
			"initContainers": [{
				"name": "init-svc",
				"image": "busybox:1.28",
				"securityContext": {"allowPrivilegeEscalation": false},
			}],
		}}},
	}

	count(res) != 0
}

test_tiller_deployed_by_metadata_name {
	res := deny with input as {
		"apiVersion": "apps/v1beta2",
		"kind": "Deployment",
		"metadata": {"name": "app-run-tiller-middle"},
		"spec": {"template": {"spec": {
			"containers": [{
				"name": "carts-db",
				"image": "mongo",
				"securityContext": {
					"runAsNonRoot": true,
					"allowPrivilegeEscalation": true,
				},
			}],
			"initContainers": [{
				"name": "init-svc",
				"image": "busybox:1.28",
				"securityContext": {"allowPrivilegeEscalation": false},
			}],
		}}},
	}

	count(res) != 0
}

test_tiller_deployed_by_spec_metadata_name {
	res := deny with input as {
		"apiVersion": "apps/v1beta2",
		"kind": "Deployment",
		"metadata": {"name": "Onga"},
		"spec": {"template": {
			"spec": {
				"containers": [{
					"name": "carts-db",
					"image": "mongo",
					"securityContext": {
						"runAsNonRoot": true,
						"allowPrivilegeEscalation": true,
					},
				}],
				"initContainers": [{
					"name": "init-svc",
					"image": "busybox:1.28",
					"securityContext": {"allowPrivilegeEscalation": false},
				}],
			},
			"metadata": {
				"name": "tiller",
				"labels": {
					"app": "example",
					"tier": "backend",
				},
			},
		}},
	}

	count(res) != 0
}

test_tiller_deployed_by_using_helm_app {
	res := deny with input as {
		"apiVersion": "apps/v1beta2",
		"kind": "Deployment",
		"metadata": {"name": "Onga"},
		"spec": {"template": {
			"spec": {
				"containers": [{
					"name": "carts-db",
					"image": "mongo",
					"securityContext": {
						"runAsNonRoot": true,
						"allowPrivilegeEscalation": true,
					},
				}],
				"initContainers": [{
					"name": "init-svc",
					"image": "busybox:1.28",
					"securityContext": {"allowPrivilegeEscalation": false},
				}],
			},
			"metadata": {
				"name": "Onag",
				"labels": {
					"app": "helm",
					"tier": "backend",
				},
			},
		}},
	}

	count(res) != 0
}

test_tiller_is_not_deployed {
	res := deny with input as {
		"apiVersion": "apps/v1beta2",
		"kind": "Deployment",
		"metadata": {"name": "Onga"},
		"spec": {"template": {
			"spec": {
				"containers": [{
					"name": "carts-db",
					"image": "mongo",
					"securityContext": {
						"runAsNonRoot": true,
						"allowPrivilegeEscalation": true,
					},
				}],
				"initContainers": [{
					"name": "init-svc",
					"image": "busybox:1.28",
					"securityContext": {"allowPrivilegeEscalation": false},
				}],
			},
			"metadata": {
				"name": "None",
				"labels": {
					"app": "example",
					"tier": "backend",
				},
			},
		}},
	}

	count(res) == 0
}
