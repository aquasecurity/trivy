package main.dockerfile.id_100

violationlist = [
  "foo"
]

violation[{"msg": msg, "details": {}}] {
	input[i].Cmd == "from"
	val := input[i].Value
	contains(val[i], violationlist[_])

	msg = sprintf("violation: image found %s", [val])
}
