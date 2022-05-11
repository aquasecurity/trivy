package builtin.dockerfile.DS009

import data.lib.docker

__rego_metadata__ := {
	"id": "DS009",
	"avd_id": "AVD-DS-0009",
	"title": "WORKDIR path not absolute",
	"short_code": "user-absolute-workdir",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "For clarity and reliability, you should always use absolute paths for your WORKDIR.",
	"recommended_actions": "Use absolute paths for your WORKDIR",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_work_dir[output] {
	workdir := docker.workdir[_]
	arg := workdir.Value[0]

	not regex.match("(^/[A-z0-9-_+]*)|(^[A-z0-9-_+]:\\\\.*)|(^\\$[{}A-z0-9-_+].*)", arg)
	output := {
		"cmd": workdir,
		"arg": arg,
	}
}

deny[res] {
	output := get_work_dir[_]
	msg := sprintf("WORKDIR path '%s' should be absolute", [output.arg])
	res := docker.result(msg, output.cmd)
}
