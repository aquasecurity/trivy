package user.terraform.ID007

__rego_metadata__ := {
	"id": "ID007",
	"title": "ASG desires too much capacity",
	"severity": "MEDIUM",
	"type": "Terraform Plan Check",
}

__rego_input__ := {"selector": [{"type": "json"}]}

deny[msg] {
	resource := input.planned_values.root_module.resources[_]
	resource.type == "aws_autoscaling_group"
	resource.values.desired_capacity > 10

	msg = sprintf("ASG '%s' desires too much capacity", [resource.name])
}
