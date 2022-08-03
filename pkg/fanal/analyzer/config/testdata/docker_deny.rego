package users.dockerfile.xyz_100

__rego_metadata__ := {
    "id": "XYZ-100",
    "title": "Bad Dockerfile",
    "version": "v1.0.0",
    "severity": "HIGH",
    "type": "Docker Security Check",
}

denylist = [
	"foo"
]

deny[res] {
	input[i].Cmd == "from"
	val := input[i].Value
	contains(val[i], denylist[_])

	res = {"type": "Docker Security Check", "msg": sprintf("deny: image found %s", [val]), "severity": "HIGH", "id": "RULE-100"}
}
