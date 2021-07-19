package user.dockerfile.ID002

__rego_metadata__ := {
	"id": "ID002",
	"title": "HTTP not allowed",
	"severity": "HIGH",
	"type": "Dockerfile Custom Check",
	"description": "HTTP should not be used.",
}

__rego_input__ := {"selector": [{"type": "dockerfile"}]}

deny[res] {
	add := input.stages[_][_]
	add.Cmd == "add"
	startswith(add.Value[0], "http://")

	res := sprintf("HTTP not allowed: '%s'", [add.Value[0]])
}
