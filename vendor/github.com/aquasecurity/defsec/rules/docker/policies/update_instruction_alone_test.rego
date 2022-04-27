package appshield.dockerfile.DS017

test_denied {
	r := deny with input as {"stages": {"ubuntu:18.04": [
		{
			"Cmd": "from",
			"Value": ["ubuntu:18.04"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get install -y --no-install-recommends mysql-client     && rm -rf /var/lib/apt/lists/*"],
		},
		{
			"Cmd": "entrypoint",
			"Value": ["mysql"],
		},
	]}}

	count(r) == 1
	trace(sprintf("%s", [r[_]]))
	r[_].msg == "The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement."
}

test_json_array_denied {
	r := deny with input as {"stages": {"ubuntu:18.04": [
		{
			"Cmd": "from",
			"Value": ["ubuntu:18.04"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get", "update"],
		},
		{
			"Cmd": "entrypoint",
			"Value": ["mysql"],
		},
	]}}

	count(r) == 1
	r[_].msg == "The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement."
}

test_chained_denied {
	r := deny with input as {"stages": {"ubuntu:18.04": [
		{
			"Cmd": "from",
			"Value": ["ubuntu:18.04"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update && adduser mike"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get install -y --no-install-recommends mysql-client     && rm -rf /var/lib/apt/lists/*"],
		},
		{
			"Cmd": "entrypoint",
			"Value": ["mysql"],
		},
	]}}

	count(r) == 1
	r[_].msg == "The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement."
}

test_allowed {
	r := deny with input as {"stages": {"ubuntu:18.04": [
		{
			"Cmd": "from",
			"Value": ["ubuntu:18.04"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update     && apt-get install -y --no-install-recommends mysql-client     && rm -rf /var/lib/apt/lists/*"],
		},
		{
			"Cmd": "run",
			"Value": ["apk update     && apk add --no-cache git ca-certificates"],
		},
		{
			"Cmd": "run",
			"Value": ["apk --update add easy-rsa"],
		},
		{
			"Cmd": "entrypoint",
			"Value": ["mysql"],
		},
	]}}

	count(r) == 0
}
