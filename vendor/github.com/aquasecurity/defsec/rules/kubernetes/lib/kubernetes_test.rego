package lib.kubernetes

test_pod {
	# spec
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-pod",
		}]},
	}

	test_pods[_].spec.containers[_].name == "hello-pod"
}

test_cron_job {
	# spec -> jobTemplate -> spec -> template -> spec
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "CronJob",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"jobTemplate": {"spec": {"template": {"spec": {
			"restartPolicy": "OnFailure",
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello !' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello-cron-job",
			}],
		}}}}},
	}

	test_pods[_].spec.containers[_].name == "hello-cron-job"
}

test_deployment {
	# spec -> template    
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "Deployment",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-deployment",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-deployment"
}

test_stateful_set {
	# spec -> template    
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "StatefulSet",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-stateful-set",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-stateful-set"
}

test_daemon_set {
	# spec -> template    
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "DaemonSet",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-daemon-set",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-daemon-set"
}

test_replica_set {
	# spec -> template    
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "ReplicaSet",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-replica-set",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-replica-set"
}

test_replication_controller {
	# spec -> template    
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "ReplicationController",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-replication-controller",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-replication-controller"
}

test_job {
	# spec -> template    
	test_pods := pods with input as {
		"apiVersion": "v1",
		"kind": "Job",
		"metadata": {"name": "hello"},
		"schedule": "*/1 * * * *",
		"spec": {"template": {"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-job",
		}]}}},
	}

	test_pods[_].spec.containers[_].name == "hello-job"
}

test_init_containers {
	test_containers := containers with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"spec": {"initContainers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-init-containers",
		}]},
	}

	test_containers[_].name == "hello-init-containers"
}

test_containers {
	test_containers := containers with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello !' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello-containers",
		}]},
	}

	test_containers[_].name == "hello-containers"
}
