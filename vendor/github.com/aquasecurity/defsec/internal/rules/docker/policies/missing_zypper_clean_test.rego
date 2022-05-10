package builtin.dockerfile.DS020

test_denied {
	r := deny with input as {"stages": {"busybox:1.0": [
		{
			"Cmd": "from",
			"Value": ["busybox:1.0"],
		},
		{
			"Cmd": "run",
			"Value": ["zypper install"],
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
	r[_].msg == "'zypper clean' is missed: 'zypper install'"
}

test_patch_denied {
	r := deny with input as {"stages": {"busybox:1.0": [
		{
			"Cmd": "from",
			"Value": ["busybox:1.0"],
		},
		{
			"Cmd": "run",
			"Value": ["zypper patch bash"],
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
	r[_].msg == "'zypper clean' is missed: 'zypper patch bash'"
}

test_wrong_order_of_commands_denied {
	r := deny with input as {"stages": {"alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["zypper cc && zypper remove bash"],
		},
	]}}

	count(r) == 1
	r[_].msg == "'zypper clean' is missed: 'zypper cc && zypper remove bash'"
}

test_multiple_install_denied {
	r := deny with input as {"stages": {"alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["zypper install bash && zypper clean && zypper remove bash"],
		},
	]}}

	count(r) == 1
	r[_].msg == "'zypper clean' is missed: 'zypper install bash && zypper clean && zypper remove bash'"
}

test_multiple_install_allowed {
	r := deny with input as {"stages": {"alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["zypper install bash && zypper clean && zypper remove bash&& zypper cc"],
		},
	]}}

	count(r) == 0
}

test_basic_allowed {
	r := deny with input as {"stages": {"alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["zypper install bash && zypper clean"],
		},
		{
			"Cmd": "run",
			"Value": ["pip install --no-cache-dir -r /usr/src/app/requirements.txt"],
		},
		{
			"Cmd": "cmd",
			"Value": [
				"python",
				"/usr/src/app/app.py",
			],
		},
	]}}

	count(r) == 0
}
