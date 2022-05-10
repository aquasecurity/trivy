package builtin.dockerfile.DS019

import data.lib.docker

__rego_metadata__ := {
	"id": "DS019",
	"avd_id": "AVD-DS-0019",
	"title": "'dnf clean all' missing",
	"short_code": "purge-dnf-package-cache",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "Cached package data should be cleaned after installation to reduce image size.",
	"recommended_actions": "Add 'dnf clean all' to Dockerfile",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

install_regex := `(dnf install)|(dnf in)|(dnf reinstall)|(dnf rei)|(dnf install-n)|(dnf install-na)|(dnf install-nevra)`

dnf_regex = sprintf("%s|(dnf clean all)", [install_regex])

get_dnf[output] {
	run := docker.run[_]
	arg := run.Value[0]

	regex.match(install_regex, arg)

	not contains_clean_after_dnf(arg)
	output := {
		"arg": arg,
		"cmd": run,
	}
}

deny[res] {
	output := get_dnf[_]
	msg := sprintf("'dnf clean all' is missed: %s", [output.arg])
	res := docker.result(msg, output.cmd)
}

contains_clean_after_dnf(cmd) {
	dnf_commands := regex.find_n(dnf_regex, cmd, -1)

	dnf_commands[count(dnf_commands) - 1] == "dnf clean all"
}
