package main.dockerfile

__rego_metadata__ := {
    "id": "XYZ-100",
    "title": "Bad Dockerfile",
    "version": "v1.0.0",
    "severity": "HIGH",
    "type": "Docker Security Check",
}

denylist = [
]

deny[msg] {
	input[i].Cmd == "from"
	val := input[i].Value
	contains(val[i], denylist[_])

	msg = sprintf("deny: image found %s", [val])
}
