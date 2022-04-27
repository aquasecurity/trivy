package appshield.dockerfile.DS013

test_basic_denied {
	r := deny with input as {"stages": {"nginx": [
		{
			"Cmd": "from",
			"Value": ["nginx"],
		},
		{
			"Cmd": "run",
			"Value": ["cd /usr/share/nginx/html"],
		},
		{
			"Cmd": "cmd",
			"Value": ["cd /usr/share/nginx/html && sed -e s/Docker/\"$AUTHOR\"/ Hello_docker.html > index.html ; nginx -g 'daemon off;'"],
		},
	]}}

	count(r) == 1
	r[_].msg == "RUN should not be used to change directory: 'cd /usr/share/nginx/html'. Use 'WORKDIR' statement instead."
}

test_chaining_denied {
	r := deny with input as {"stages": {"nginx": [
		{
			"Cmd": "from",
			"Value": ["nginx"],
		},
		{
			"Cmd": "env",
			"Value": [
				"AUTHOR",
				"Docker",
			],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get install vim && cd /usr/share/nginx/html"],
		},
		{
			"Cmd": "cmd",
			"Value": ["cd /usr/share/nginx/html && sed -e s/Docker/\"$AUTHOR\"/ Hello_docker.html > index.html ; nginx -g 'daemon off;'"],
		},
	]}}

	count(r) == 1
	r[_].msg == "RUN should not be used to change directory: 'apt-get install vim && cd /usr/share/nginx/html'. Use 'WORKDIR' statement instead."
}

test_basic_allowed {
	r := deny with input as {"stages": {"nginx": [
		{
			"Cmd": "from",
			"Value": ["nginx"],
		},
		{
			"Cmd": "workdir",
			"Value": ["/usr/share/nginx/html"],
		},
		{
			"Cmd": "copy",
			"Value": [
				"Hello_docker.html",
				"/usr/share/nginx/html",
			],
		},
		{
			"Cmd": "cmd",
			"Value": ["cd /usr/share/nginx/html && sed -e s/Docker/\"$AUTHOR\"/ Hello_docker.html > index.html ; nginx -g 'daemon off;'"],
		},
	]}}

	count(r) == 0
}
