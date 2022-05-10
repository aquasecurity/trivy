package builtin.dockerfile.DS016

test_denied {
	r := deny with input as {"stages": {
		"golang:1.7.3": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3"],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
			{
				"Cmd": "cmd",
				"Value": ["./apps"],
			},
		],
		"alpine:latest": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		],
	}}

	count(r) == 1
	r[_].msg == "There are 2 duplicate CMD instructions for stage 'golang:1.7.3'"
}

test_allowed {
	r := deny with input as {"stages": {
		"golang:1.7.3": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3"],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		],
		"alpine:latest": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		],
	}}

	count(r) == 0
}
