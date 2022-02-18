package user.hcl.ID004

test_denied {
	deny[msg] with input as {
		"environment": "dev",
		"service": {"http": {"web_proxy": [{
			"listen_addr": "0.0.0.0:8080",
			"process": {
				"main": [{"command": [
					"/usr/local/bin/awesome-app",
					"server",
				]}],
				"mgmt": [{"command": [
					"/usr/local/bin/awesome-app",
					"mgmt",
				]}],
			},
		}]}},
	}

	msg == "'web_proxy' listens on 0.0.0.0 in dev environment"
}

test_allowed {
	r := deny with input as {
		"environment": "dev",
		"service": {"http": {"web_proxy": [{
			"listen_addr": "127.0.0.1:8080",
			"process": {
				"main": [{"command": [
					"/usr/local/bin/awesome-app",
					"server",
				]}],
				"mgmt": [{"command": [
					"/usr/local/bin/awesome-app",
					"mgmt",
				]}],
			},
		}]}},
	}

	count(r) == 0
}
