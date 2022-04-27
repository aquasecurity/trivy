package appshield.dockerfile.DS015

test_basic_denied {
	r := deny with input as {"stages": {
		"alpine:3.5": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.5"],
			},
			{
				"Cmd": "run",
				"Value": ["yum install vim"],
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
		],
		"alpine:3.4": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.4"],
			},
			{
				"Cmd": "run",
				"Value": ["yum -y install vim && yum clean all"],
			},
		],
	}}

	count(r) == 1
	r[_].msg == "'yum clean all' is missed: yum install vim"
}

test_wrong_order_of_commands_denied {
	r := deny with input as {"stages": {"alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["yum clean all && yum -y install"],
		},
	]}}

	count(r) == 1
	r[_].msg == "'yum clean all' is missed: yum clean all && yum -y install"
}

test_multiple_install_denied {
	r := deny with input as {"stages": {"alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["yum -y install bash && yum clean all && yum -y install zsh"],
		},
	]}}

	count(r) == 1
	r[_].msg == "'yum clean all' is missed: yum -y install bash && yum clean all && yum -y install zsh"
}

test_multiple_install_allowed {
	r := deny with input as {"stages": {"alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["yum -y install bash && yum clean all && yum -y install zsh && yum clean all"],
		},
	]}}

	count(r) == 0
}

test_basic_allowed {
	r := deny with input as {"stages": {
		"alpine:3.5": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.5"],
			},
			{
				"Cmd": "run",
				"Value": ["yum install && yum clean all"],
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
		],
		"alpine:3.4": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.4"],
			},
			{
				"Cmd": "run",
				"Value": ["yum -y install && yum clean all"],
			},
		],
	}}

	count(r) == 0
}
