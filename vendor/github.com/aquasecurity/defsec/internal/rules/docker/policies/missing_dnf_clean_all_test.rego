package builtin.dockerfile.DS019

test_denied {
	r := deny with input as {"stages": {"fedora:27": [
		{
			"Cmd": "from",
			"Value": ["fedora:27"],
		},
		{
			"Cmd": "run",
			"Value": ["set -uex &&     dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo &&     sed -i 's/\\$releasever/26/g' /etc/yum.repos.d/docker-ce.repo &&     dnf install -vy docker-ce"],
		},
		{
			"Cmd": "healthcheck",
			"Value": [
				"CMD",
				"curl --fail http://localhost:3000 || exit 1",
			],
		},
	]}}

	count(r) == 1
	r[_].msg == "'dnf clean all' is missed: set -uex &&     dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo &&     sed -i 's/\\$releasever/26/g' /etc/yum.repos.d/docker-ce.repo &&     dnf install -vy docker-ce"
}

test_allowed {
	r := deny with input as {"stages": {"fedora:27": [
		{
			"Cmd": "from",
			"Value": ["fedora:27"],
		},
		{
			"Cmd": "run",
			"Value": ["set -uex &&     dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo &&     sed -i 's/\\$releasever/26/g' /etc/yum.repos.d/docker-ce.repo &&     dnf install -vy docker-ce &&     dnf clean all"],
		},
		{
			"Cmd": "healthcheck",
			"Value": [
				"CMD",
				"curl --fail http://localhost:3000 || exit 1",
			],
		},
	]}}

	count(r) == 0
}

test_wrong_order_of_commands_denied {
	r := deny with input as {"stages": {"alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["dnf clean all && dnf install -vy docker-ce"],
		},
	]}}

	count(r) == 1
	r[_].msg == "'dnf clean all' is missed: dnf clean all && dnf install -vy docker-ce"
}

test_multiple_install_denied {
	r := deny with input as {"stages": {"alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["dnf install bash && dnf clean all && dnf install zsh"],
		},
	]}}

	count(r) == 1
	r[_].msg == "'dnf clean all' is missed: dnf install bash && dnf clean all && dnf install zsh"
}

test_multiple_install_allowed {
	r := deny with input as {"stages": {"alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["dnf install bash && dnf clean all && dnf install zsh && dnf clean all"],
		},
	]}}

	count(r) == 0
}
