package appshield.dockerfile.DS012

test_basic_denied {
	r := deny with input as {"stages": {
		"baseImage as bi": [
			{
				"Cmd": "from",
				"Value": ["baseImage"],
			},
			{
				"Cmd": "run",
				"Value": ["Test"],
			},
		],
		"debian:jesse2 as build": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse2",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["stuff"],
			},
		],
		"debian:jesse1 as build": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse1",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["more_stuff"],
			},
		],
	}}

	count(r) == 1
	r[_].msg == "Duplicate aliases 'build' are found in different FROMs"
}

test_missed_alias_denied {
	r := deny with input as {"stages": {
		"baseImage": [
			{
				"Cmd": "from",
				"Value": ["baseImage"],
			},
			{
				"Cmd": "run",
				"Value": ["Test"],
			},
		],
		"debian:jesse2 as build": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse2",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["stuff"],
			},
		],
		"debian:jesse1 as build": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse1",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["more_stuff"],
			},
		],
	}}

	count(r) == 1
	r[_].msg == "Duplicate aliases 'build' are found in different FROMs"
}

test_no_alias_allowed {
	r := deny with input as {"stages": {
		"baseImage": [
			{
				"Cmd": "from",
				"Value": ["baseImage"],
			},
			{
				"Cmd": "run",
				"Value": ["Test"],
			},
		],
		"debian:jesse2": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse2",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["stuff"],
			},
		],
	}}

	count(r) == 0
}

test_extra_spaces_denied {
	r := deny with input as {"stages": {
		"baseImage": [
			{
				"Cmd": "from",
				"Value": ["baseImage"],
			},
			{
				"Cmd": "run",
				"Value": ["Test"],
			},
		],
		"debian:jesse2 as build": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse2",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["stuff"],
			},
		],
		"debian:jesse1 as    build": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse1",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["more_stuff"],
			},
		],
	}}

	count(r) == 1
	r[_].msg == "Duplicate aliases 'build' are found in different FROMs"
}

test_basic_allowed {
	r := deny with input as {"stages": {
		"baseImage": [
			{
				"Cmd": "from",
				"Value": ["baseImage"],
			},
			{
				"Cmd": "run",
				"Value": ["Test"],
			},
		],
		"debian:jesse2 as build2": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse2",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["stuff"],
			},
		],
		"debian:jesse1 as build1": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse1",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["more_stuff"],
			},
		],
	}}

	count(r) == 0
}
