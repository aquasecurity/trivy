package user.dockerfile.ID002

test_http_denied {
	r := deny with input as {"Stages": [{"Name": "alpine:3.31", "Commands": [
		{"Cmd": "from", "Value": ["alpine:3.13"]},
		{"Cmd": "add", "Value": ["http://example.com/big.tar.xz", "/usr/src/things/"]},
		{"Cmd": "run", "Value": ["tar -xJf /usr/src/things/big.tar.xz -C /usr/src/things"]},
	]}]}

	count(r) == 1
	r[_] == "HTTP not allowed: 'http://example.com/big.tar.xz'"
}

test_http_allowed {
	r := deny with input as {"Stages": [{"Name": "alpine:3.31", "Commands": [
		{"Cmd": "from", "Value": ["alpine:3.13"]},
		{"Cmd": "add", "Value": ["https://example.com/big.tar.xz", "/usr/src/things/"]},
	]}]}

	count(r) == 0
}
