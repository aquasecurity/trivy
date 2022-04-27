package appshield.dockerfile.DS009

test_basic_denied {
	r := deny with input as {"stages": {"alpine:3.5": [
		{"Cmd": "from", "Value": ["alpine:3.5"]},
		{
			"Cmd": "run",
			"Value": ["apk add --update py2-pip"],
		},
		{
			"Cmd": "workdir",
			"Value": ["/path/to/workdir"],
		},
		{
			"Cmd": "workdir",
			"Value": ["workdir"],
		},
	]}}

	count(r) == 1
	r[_].msg == "WORKDIR path 'workdir' should be absolute"
}

test_no_work_dir_allowed {
	r := deny with input as {"stages": {"alpine:3.3": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.3"],
		},
		{
			"Cmd": "run",
			"Value": ["apk --no-cache add nginx"],
		},
	]}}

	count(r) == 0
}

test_absolute_work_dir_allowed {
	r := deny with input as {"stages": {"alpine:3.3": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.3"],
		},
		{
			"Cmd": "run",
			"Value": ["apk --no-cache add nginx"],
		},
		{
			"Cmd": "workdir",
			"Value": ["/path/to/workdir"],
		},
	]}}

	count(r) == 0
}
