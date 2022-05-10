package builtin.dockerfile.DS021

import data.lib.docker

__rego_metadata__ := {
	"id": "DS021",
	"avd_id": "AVD-DS-0021",
	"title": "'apt-get' missing '-y' to avoid manual input",
	"short_code": "use-apt-auto-confirm",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "'apt-get' calls should use the flag '-y' to avoid manual user input.",
	"recommended_actions": "Add '-y' flag to 'apt-get'",
	"url": "https://docs.docker.com/engine/reference/builder/#run",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
	output := get_apt_get[_]
	msg := sprintf("'-y' flag is missed: '%s'", [output.arg])
	res := docker.result(msg, output.cmd)
}

get_apt_get[output] {
	run = docker.run[_]

	count(run.Value) == 1
	arg := run.Value[0]

	is_apt_get(arg)

	not includes_assume_yes(arg)

	output := {
		"arg": arg,
		"cmd": run,
	}
}

# checking json array
get_apt_get[output] {
	run = docker.run[_]

	count(run.Value) > 1

	arg := concat(" ", run.Value)

	is_apt_get(arg)

	not includes_assume_yes(arg)

	output := {
		"arg": arg,
		"cmd": run,
	}
}

is_apt_get(command) {
	regex.match("apt-get (-(-)?[a-zA-Z]+ *)*install(-(-)?[a-zA-Z]+ *)*", command)
}

short_flags := `(-([a-xzA-XZ])*y([a-xzA-XZ])*)`

long_flags := `(--yes)|(--assume-yes)`

optional_not_related_flags := `\s*(-(-)?[a-zA-Z]+\s*)*`

combined_flags := sprintf(`%s(%s|%s)%s`, [optional_not_related_flags, short_flags, long_flags, optional_not_related_flags])

# flags before command
includes_assume_yes(command) {
	install_regexp := sprintf(`apt-get%sinstall`, [combined_flags])
	regex.match(install_regexp, command)
}

# flags behind command
includes_assume_yes(command) {
	install_regexp := sprintf(`apt-get%sinstall%s`, [optional_not_related_flags, combined_flags])
	regex.match(install_regexp, command)
}
