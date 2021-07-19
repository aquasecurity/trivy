package user.serverless.ID005

__rego_metadata__ := {
	"id": "ID005",
	"title": "Python 2.7",
	"severity": "CRITICAL",
	"type": "Python 2.7 should not be used.",
}

__rego_input__ := {"selector": [{"type": "yaml"}]}

deny[msg] {
	input.provider.runtime = "python2.7"
	msg = "Python 2.7 should not be the default provider runtime"
}
