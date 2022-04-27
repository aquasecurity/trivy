package appshield.dockerfile.DS012

import data.lib.docker

__rego_metadata__ := {
	"id": "DS012",
	"avd_id": "AVD-DS-0012",
	"title": "Duplicate aliases defined in different FROMs",
	"short_code": "no-duplicate-alias",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "Different FROMs can't have the same alias defined.",
	"recommended_actions": "Change aliases to make them different",
	"url": "https://docs.docker.com/develop/develop-images/multistage-build/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_duplicate_alias[output] {
	output1 := get_aliased_name[_]
	output2 := get_aliased_name[_]
	output1.arg != output2.arg

	[_, alias1] := regex.split(`\s+as\s+`, output1.arg)
	[_, alias2] := regex.split(`\s+as\s+`, output2.arg)
	alias1 == alias2
	output := {
		"alias": alias1,
		"cmd": output1.cmd,
	}
}

get_aliased_name[output] {
	some name
	stage := input.stages[name]

	cmd := stage[0]

	arg = lower(name)
	contains(arg, " as ")
	output := {
		"arg": arg,
		"cmd": cmd,
	}
}

deny[res] {
	output := get_duplicate_alias[_]
	msg := sprintf("Duplicate aliases '%s' are found in different FROMs", [output.alias])
	res := docker.result(msg, output.cmd)
}
