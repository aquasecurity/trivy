package builtin.dockerfile.DS018

test_denied {
	r := deny with input as {"stages": {
		"golang:1.7.3 as dep": [
			{
				"Cmd": "from",
				"Stage": 0,
				"Value": [
					"golang:1.7.3",
					"AS",
					"builder",
				],
			},
			{
				"Cmd": "run",
				"Stage": 0,
				"Value": ["CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app ."],
			},
		],
		"alpine:latest": [
			{
				"Cmd": "from",
				"Stage": 1,
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "copy",
				"Stage": 1,
				"Flags": ["--from=builder2"],
				"Value": [
					"/go/src/github.com/alexellis/href-counter/app",
					".",
				],
			},
			{
				"Cmd": "cmd",
				"Stage": 1,
				"Value": ["./app"],
			},
		],
	}}

	count(r) == 1
	r[_].msg == "The alias '--from=builder2' is not defined in the previous stages"
}

test_allowed {
	r := deny with input as {"stages": {
		"golang:1.7.3 as dep": [
			{
				"Cmd": "from",
				"Stage": 0,
				"Value": [
					"golang:1.7.3",
					"AS",
					"builder",
				],
			},
			{
				"Cmd": "run",
				"Value": ["CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app ."],
			},
		],
		"alpine:latest": [
			{
				"Cmd": "from",
				"Stage": 1,
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "copy",
				"Stage": 1,
				"Flags": ["--from=dep"],
				"Value": [
					"/go/src/github.com/alexellis/href-counter/app",
					".",
				],
			},
			{
				"Cmd": "cmd",
				"Stage": 1,
				"Value": ["./app"],
			},
		],
	}}

	count(r) == 0
}

test_stage_index_allowed {
	r := deny with input as {"stages": {
		"golang:1.7.3 as dep": [
			{
				"Cmd": "from",
				"Stage": 0,
				"Value": [
					"golang:1.7.3",
					"AS",
					"builder",
				],
			},
			{
				"Cmd": "run",
				"Stage": 0,
				"Value": ["CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app ."],
			},
		],
		"alpine:latest": [
			{
				"Cmd": "from",
				"Stage": 1,
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "copy",
				"Stage": 1,
				"Flags": ["--from=0"],
				"Value": [
					"/go/src/github.com/alexellis/href-counter/app",
					".",
				],
			},
			{
				"Cmd": "cmd",
				"Stage": 1,
				"Value": ["./app"],
			},
		],
	}}

	count(r) == 0
}

test_from_next_stage_denied {
	r := deny with input as {"stages": {
		"golang:1.7.3 as build1": [
			{
				"Cmd": "from",
				"Stage": 0,
				"Value": [
					"golang:1.7.3",
					"AS",
					"builder",
				],
			},
			{
				"Cmd": "run",
				"Stage": 0,
				"Value": ["CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app1 ."],
			},
		],
		"golang:1.7.3 as build2": [
			{
				"Cmd": "from",
				"Stage": 1,
				"Value": [
					"golang:1.7.3",
					"AS",
					"builder",
				],
			},
			{
				"Cmd": "copy",
				"Stage": 1,
				"Flags": ["--from=build3"],
				"Value": [
					"/go/src/github.com/alexellis/href-counter/app",
					".",
				],
			},
			{
				"Cmd": "run",
				"Stage": 1,
				"Value": ["CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app2 ."],
			},
		],
		"golang:1.7.3 as build3": [
			{
				"Cmd": "from",
				"Stage": 2,
				"Value": [
					"golang:1.7.3",
					"AS",
					"builder",
				],
			},
			{
				"Cmd": "run",
				"Stage": 2,
				"Value": ["CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app3 ."],
			},
		],
		"alpine:latest": [
			{
				"Cmd": "from",
				"Stage": 3,
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "copy",
				"Stage": 3,
				"Flags": ["--from=build1"],
				"Value": [
					"/go/src/github.com/alexellis/href-counter/app",
					".",
				],
			},
			{
				"Cmd": "cmd",
				"Stage": 3,
				"Value": ["./app"],
			},
		],
	}}

	count(r) == 1
	r[_].msg == "The alias '--from=build3' is not defined in the previous stages"
}
