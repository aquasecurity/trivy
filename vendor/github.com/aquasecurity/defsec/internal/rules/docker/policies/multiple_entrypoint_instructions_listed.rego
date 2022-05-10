package builtin.dockerfile.DS007

import data.lib.docker

__rego_metadata__ := {
	"id": "DS007",
	"avd_id": "AVD-DS-0007",
	"title": "Multiple ENTRYPOINT instructions listed",
	"short_code": "only-one-entrypoint",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "There can only be one ENTRYPOINT instruction in a Dockerfile. Only the last ENTRYPOINT instruction in the Dockerfile will have an effect.",
	"recommended_actions": "Remove unnecessary ENTRYPOINT instruction.",
	"url": "https://docs.docker.com/engine/reference/builder/#entrypoint",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
	entrypoints := docker.stage_entrypoints[name]
	count(entrypoints) > 1
	msg := sprintf("There are %d duplicate ENTRYPOINT instructions for stage '%s'", [count(entrypoints), name])
	res := docker.result(msg, entrypoints[1])
}
