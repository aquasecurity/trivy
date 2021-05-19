package main.dockerfile

denylist = [
	"foo"
]

deny[res] {
	input[i].Cmd == "from"
	val := input[i].Value
	contains(val[i], denylist[_])

	res = {
		"type": "Docker Security Check",
		"msg": sprintf("deny: image found %s", [val]),
		"severity": "HIGH",
		"id": "RULE-100"
	}
}

warnlist = [
	"echo"
]

warn[res] {
	input[i].Cmd == "run"
	val := input[i].Value
	contains(val[_], warnlist[_])

	res = {
		"type": "Docker Security Check",
		"msg": sprintf("warn: command %s contains banned: %s", [val, warnlist]),
		"severity": "LOW",
		"id": "RULE-10"
	}
}
