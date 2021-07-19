package user.kubernetes.ID001

__rego_metadata__ := {
	"id": "ID001",
	"title": "Deployment not allowed",
	"severity": "HIGH",
	"type": "Kubernetes Custom Check",
	"description": "Deployments are not allowed because of some reasons.",
}

__rego_input__ := {"selector": [{"type": "kubernetes"}]}

deny[msg] {
	input.kind == "Deployment"
	msg = sprintf("Found deployment '%s' but deployments are not allowed", [input.metadata.name])
}
