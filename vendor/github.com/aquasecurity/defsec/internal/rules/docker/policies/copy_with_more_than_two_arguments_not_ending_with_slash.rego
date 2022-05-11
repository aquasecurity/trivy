package builtin.dockerfile.DS011

import data.lib.docker

__rego_metadata__ := {
	"id": "DS011",
	"avd_id": "AVD-DS-0011",
	"title": "COPY with more than two arguments not ending with slash",
	"short_code": "use-slash-for-copy-args",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "When a COPY command has more than two arguments, the last one should end with a slash.",
	"recommended_actions": "Add slash to last COPY argument",
	"url": "https://docs.docker.com/engine/reference/builder/#copy",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_copy_arg[output] {
	copy := docker.copy[_]

	cnt := count(copy.Value)
	cnt > 2

	arg := copy.Value[cnt - 1]
	not endswith(arg, "/")
	output := {
		"arg": arg,
		"cmd": copy,
	}
}

deny[res] {
	output := get_copy_arg[_]
	msg := sprintf("Slash is expected at the end of COPY command argument '%s'", [output.arg])
	res := docker.result(msg, output.cmd)
}
