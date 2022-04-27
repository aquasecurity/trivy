package appshield.dockerfile.DS023

import data.lib.docker

__rego_metadata__ := {
	"id": "DS023",
	"avd_id": "AVD-DS-0023",
	"title": "Multiple HEALTHCHECK defined",
	"short_code": "only-one-healthcheck",
	"severity": "MEDIUM",
	"type": "Dockerfile Security Check",
	"description": "Providing more than one HEALTHCHECK instruction per stage is confusing and error-prone.",
	"recommended_actions": "One HEALTHCHECK instruction must remain in Dockerfile. Remove all other instructions.",
	"url": "https://docs.docker.com/engine/reference/builder/#healthcheck",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
	healthchecks := docker.stage_healthcheck[name]
	cnt := count(healthchecks)
	cnt > 1
	msg := sprintf("There are %d duplicate HEALTHCHECK instructions in the stage '%s'", [cnt, name])
	res := docker.result(msg, healthchecks[1])
}
