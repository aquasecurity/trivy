package main.dockerfile.xyz_100

__rego_metadata__ := {
    "id": "XYZ-100",
    "title": "Bad Dockerfile",
    "version": "v1.0.0",
}

warnlist = [
	"foo"
]

warn[msg] {
	input[i].Cmd == "from"
	val := input[i].Value
	contains(val[i], warnlist[_])

	msg = sprintf("warn: image found %s", [val])
}
