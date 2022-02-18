package user.hcl.ID004

__rego_metadata__ := {
	"id": "ID004",
	"title": "Listen on 0.0.0.0",
	"severity": "CRITICAL",
	"type": "HCL Custom Check",
}

__rego_input__ := {"selector": [{"type": "hcl"}]}

deny[msg] {
	input.environment == "dev"
	contains(input.service.http[name][_].listen_addr, "0.0.0.0")
	msg = sprintf("'%s' listens on 0.0.0.0 in dev environment", [name])
}
