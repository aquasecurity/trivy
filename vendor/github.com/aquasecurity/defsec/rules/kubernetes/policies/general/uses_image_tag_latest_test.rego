package appshield.kubernetes.KSV013

test_image_with_no_tag_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-tag"},
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

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-tag' should specify an image tag"
}

test_image_uses_latest_tag_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-tag"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox:latest",
			"name": "hello",
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-tag' should specify an image tag"
}

test_tagged_image_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-tag"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox:1.33.1",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_tagged_image_with_digest_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-tag"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox:1.33.1@sha256:askj78jhkf278hdjkf78623gbkljmkvmk8kjn98237487hkjaf897bkjsehf783f",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_image_uses_latest_tag_with_digest_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-tag"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox:latest@sha256:askj78jhkf278hdjkf78623gbkljmkvmk8kjn98237487hkjaf897bkjsehf783f",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_image_with_no_tag_with_digest_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-tag"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox@sha256:askj78jhkf278hdjkf78623gbkljmkvmk8kjn98237487hkjaf897bkjsehf783f",
			"name": "hello",
		}]},
	}

	count(r) == 0
}
