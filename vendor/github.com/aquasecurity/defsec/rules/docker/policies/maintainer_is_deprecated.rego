package appshield.dockerfile.DS022

import data.lib.docker

__rego_metadata__ := {
	"id": "DS022",
	"avd_id": "AVD-DS-0022",
	"title": "Deprecated MAINTAINER used",
	"short_code": "no-maintainer",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "MAINTAINER has been deprecated since Docker 1.13.0.",
	"recommended_actions": "Use LABEL instead of MAINTAINER",
	"url": "https://docs.docker.com/engine/deprecated/#maintainer-in-dockerfile",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_maintainer[mntnr] {
	mntnr := input.stages[_][_]
	mntnr.Cmd == "maintainer"
}

deny[res] {
	mntnr := get_maintainer[_]
	msg := sprintf("MAINTAINER should not be used: 'MAINTAINER %s'", [mntnr.Value[0]])
	res := docker.result(msg, mntnr)
}
