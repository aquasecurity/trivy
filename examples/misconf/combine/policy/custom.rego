package user.kubernetes.ID003

__rego_metadata__ := {
	"id": "ID003",
	"title": "Servide does not target Pod",
	"severity": "CRITICAL",
	"type": "Kubernetes Custom Check",
	"description": "Service selector does not match any Pod label",
}

__rego_input__ := {
	"combine": true,
	"selector": [{"type": "kubernetes"}],
}

deny[res] {
	service := input[i].contents
	service.kind == "Service"
	value := service.spec.selector[key]
	not match_label(key, value)

	res := {
		"filepath": input[i].path,
		"msg": sprintf("Service '%s' selector does not match with any Pod label", [service.metadata.name]),
	}
}

match_label(key, value) {
	deployment := input[i].contents
	deployment.kind == "Deployment"
	deployment.spec.template.metadata.labels[key] == value
}
