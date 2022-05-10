package builtin.dockerfile.DS013

import data.lib.docker

__rego_metadata__ := {
	"id": "DS013",
	"avd_id": "AVD-DS-0013",
	"title": "'RUN cd ...' to change directory",
	"short_code": "use-workdir-over-cd",
	"severity": "MEDIUM",
	"type": "Dockerfile Security Check",
	"description": "Use WORKDIR instead of proliferating instructions like 'RUN cd … && do-something', which are hard to read, troubleshoot, and maintain.",
	"recommended_actions": "Use WORKDIR to change directory",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_cd[output] {
	run := docker.run[_]
	parts = regex.split(`\s*&&\s*`, run.Value[_])
	startswith(parts[_], "cd ")
	args := concat(" ", run.Value)
	output := {
		"args": args,
		"cmd": run,
	}
}

deny[res] {
	output := get_cd[_]
	msg := sprintf("RUN should not be used to change directory: '%s'. Use 'WORKDIR' statement instead.", [output.args])
	res := docker.result(msg, output.cmd)
}
