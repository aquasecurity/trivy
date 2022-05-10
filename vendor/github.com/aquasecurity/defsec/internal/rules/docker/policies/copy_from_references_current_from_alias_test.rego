package builtin.dockerfile.DS006

test_basic_denied {
	r := deny with input as {"stages": {
		"golang:1.7.3 as dep": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3", "as", "dep"],
			},
			{
				"Cmd": "copy",
				"Flags": ["--from=dep"],
				"Value": [
					"/binary",
					"/",
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
	r[_].msg == "'COPY --from' should not mention current alias 'dep' since it is impossible to copy from itself"
}

test_extra_spaces_denied {
	r := deny with input as {"stages": {
		"golang:1.7.3 as   dep": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3"],
			},
			{
				"Cmd": "copy",
				"Flags": ["--from=dep"],
				"Value": [
					"/binary",
					"/",
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
	r[_].msg == "'COPY --from' should not mention current alias 'dep' since it is impossible to copy from itself"
}

test_basic_allowed {
	r := deny with input as {"stages": {
		"golang:1.7.3 AS builder": [
			{
				"Cmd": "from",
				"Value": [
					"golang:1.7.3",
					"AS",
					"builder",
				],
			},
			{
				"Cmd": "workdir",
				"Value": ["/go/src/github.com/alexellis/href-counter/"],
			},
			{
				"Cmd": "run",
				"Value": ["go get -d -v golang.org/x/net/html"],
			},
			{
				"Cmd": "copy",
				"Value": [
					"app.go",
					".",
				],
			},
			{
				"Cmd": "run",
				"Value": ["CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app ."],
			},
			{
				"Cmd": "comment",
				"Value": ["another dockerfile"],
			},
		],
		"alpine:latest": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "run",
				"Value": ["apk --no-cache add ca-certificates"],
			},
			{
				"Cmd": "workdir",
				"Value": ["/root/"],
			},
			{
				"Cmd": "copy",
				"Flags": ["--from=builder"],
				"Value": [
					"/go/src/github.com/alexellis/href-counter/app",
					".",
				],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		],
	}}

	count(r) == 0
}
