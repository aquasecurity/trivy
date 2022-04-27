package appshield.dockerfile.DS015

import data.lib.docker

__rego_metadata__ := {
	"id": "DS015",
	"avd_id": "AVD-DS-0015",
	"title": "'yum clean all' missing",
	"short_code": "purge-yum-package-cache",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "You should use 'yum clean all' after using a 'yum install' command to clean package cached data and reduce image size.",
	"recommended_actions": "Add 'yum clean all' to Dockerfile",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_yum[output] {
	run := docker.run[_]
	arg := run.Value[0]

	regex.match("yum (-[a-zA-Z]+ *)*install", arg)

	not contains_clean_after_yum(arg)
	output := {
		"cmd": run,
		"arg": arg,
	}
}

deny[res] {
	output := get_yum[_]
	msg := sprintf("'yum clean all' is missed: %s", [output.arg])
	res := docker.result(msg, output.cmd)
}

contains_clean_after_yum(cmd) {
	yum_commands := regex.find_n("(yum (-[a-zA-Z]+ *)*install)|(yum clean all)", cmd, -1)

	yum_commands[count(yum_commands) - 1] == "yum clean all"
}
