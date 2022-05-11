package builtin.kubernetes.KSV037

test_pod_with_default_namespace {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"creationTimestamp": "2022-01-12T10:28:20Z",
			"labels": {
				"app": "redis",
				"role": "master",
				"tier": "backend",
			},
			"name": "redis-master-85547b7b9-fxnrp",
			"namespace": "default",
			"resourceVersion": "443282",
		},
		"spec": {"containers": [{
			"image": "redis",
			"imagePullPolicy": "Always",
			"name": "master",
			"terminationMessagePath": "/dev/termination-log",
			"terminationMessagePolicy": "File",
			"volumeMounts": [{
				"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
				"name": "kube-api-access-85g42",
				"readOnly": true,
			}],
		}]},
	}

	count(r) == 0
}

test_pod_core_component {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"creationTimestamp": "2022-01-12T10:28:20Z",
			"labels": {
				"component": "kube-apiserver",
				"app": "redis",
				"role": "master",
				"tier": "control-plane",
			},
			"name": "redis-master-85547b7b9-fxnrp",
			"namespace": "kube-system",
			"resourceVersion": "443282",
		},
		"spec": {
			"containers": [{
				"image": "redis",
				"imagePullPolicy": "Always",
				"name": "master",
				"terminationMessagePath": "/dev/termination-log",
				"terminationMessagePolicy": "File",
				"volumeMounts": [{
					"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
					"name": "kube-api-access-85g42",
					"readOnly": true,
				}],
			}],
			"priorityClassName": "system-node-critical",
		},
	}

	count(r) == 0
}

test_pod_non_core_component_with_kube_system_namespace_no_label_component {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"creationTimestamp": "2022-01-12T10:28:20Z",
			"labels": {
				"app": "redis",
				"role": "master",
				"tier": "control-plane",
			},
			"name": "redis-master-85547b7b9-fxnrp",
			"namespace": "kube-system",
			"resourceVersion": "443282",
		},
		"spec": {
			"containers": [{
				"image": "redis",
				"imagePullPolicy": "Always",
				"name": "master",
				"terminationMessagePath": "/dev/termination-log",
				"terminationMessagePolicy": "File",
				"volumeMounts": [{
					"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
					"name": "kube-api-access-85g42",
					"readOnly": true,
				}],
			}],
			"priorityClassName": "system-node-critical",
		},
	}

	r[_].msg == "Pod 'redis-master-85547b7b9-fxnrp' should not be set with 'kube-system' namespace"
}

test_pod_non_core_component_with_kube_system_namespace_wrong_label_tier {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"creationTimestamp": "2022-01-12T10:28:20Z",
			"labels": {
				"component": "kube-apiserver",
				"app": "redis",
				"role": "master",
				"tier": "backend",
			},
			"name": "redis-master-85547b7b9-fxnrp",
			"namespace": "kube-system",
			"resourceVersion": "443282",
		},
		"spec": {
			"containers": [{
				"image": "redis",
				"imagePullPolicy": "Always",
				"name": "master",
				"terminationMessagePath": "/dev/termination-log",
				"terminationMessagePolicy": "File",
				"volumeMounts": [{
					"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
					"name": "kube-api-access-85g42",
					"readOnly": true,
				}],
			}],
			"priorityClassName": "system-node-critical",
		},
	}

	r[_].msg == "Pod 'redis-master-85547b7b9-fxnrp' should not be set with 'kube-system' namespace"
}

test_pod_non_core_component_with_kube_system_namespace_no_priority_class_name {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"creationTimestamp": "2022-01-12T10:28:20Z",
			"labels": {
				"component": "kube-apiserver",
				"app": "redis",
				"role": "master",
				"tier": "backend",
			},
			"name": "redis-master-85547b7b9-fxnrp",
			"namespace": "kube-system",
			"resourceVersion": "443282",
		},
		"spec": {
			"containers": [{
				"image": "redis",
				"imagePullPolicy": "Always",
				"name": "master",
				"terminationMessagePath": "/dev/termination-log",
				"terminationMessagePolicy": "File",
				"volumeMounts": [{
					"mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
					"name": "kube-api-access-85g42",
					"readOnly": true,
				}],
			}],
			"priorityClassName": "system-node-critical",
		},
	}

	r[_].msg == "Pod 'redis-master-85547b7b9-fxnrp' should not be set with 'kube-system' namespace"
}
