package builtin.dockerfile.DS007

test_denied {
	r := deny with input as {"stages": {
		"golang": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3"],
			},
			{
				"Cmd": "entrypoint",
				"Value": [
					"/opt/app/run.sh",
					"--port",
					"8080",
				],
			},
			{
				"Cmd": "entrypoint",
				"Value": [
					"/opt/app/run.sh",
					"--port",
					"8000",
				],
			},
		],
		"alpine": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "entrypoint",
				"Value": [
					"/opt/app/run.sh",
					"--port",
					"8080",
				],
			},
		],
	}}

	count(r) == 1
	r[_].msg == "There are 2 duplicate ENTRYPOINT instructions for stage 'golang'"
}

test_allowed {
	r := deny with input as {"stages": {
		"golang": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3"],
			},
			{
				"Cmd": "entrypoint",
				"Value": [
					"/opt/app/run.sh",
					"--port",
					"8080",
				],
			},
		],
		"alpine": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "entrypoint",
				"Value": [
					"/opt/app/run.sh",
					"--port",
					"8080",
				],
			},
		],
	}}

	count(r) == 0
}
