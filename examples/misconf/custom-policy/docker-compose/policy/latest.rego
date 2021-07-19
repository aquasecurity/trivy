package user.compose.ID003

__rego_metadata__ := {
	"id": "ID003",
	"title": "latest not allowed",
	"severity": "MEDIUM",
	"type": "Docker Compose Custom Check",
	"description": "The latest tag should not be used.",
}

__rego_input__ := {"selector": [{"type": "yaml"}]}

deny[msg] {
    endswith(input.services[_].image, ":latest")

	msg := "':latest' tag is not allowed"
}
