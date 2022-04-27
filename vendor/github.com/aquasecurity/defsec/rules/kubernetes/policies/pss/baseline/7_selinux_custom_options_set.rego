package appshield.kubernetes.KSV025

import data.lib.kubernetes
import data.lib.utils

default failSELinux = false

__rego_metadata__ := {
	"id": "KSV025",
	"avd_id": "AVD-KSV-0025",
	"title": "SELinux custom options set",
	"short_code": "no-custom-selinux-options",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "Setting a custom SELinux user or role option should be forbidden.",
	"recommended_actions": "Do not set 'spec.securityContext.seLinuxOptions', spec.containers[*].securityContext.seLinuxOptions and spec.initContainers[*].securityContext.seLinuxOptions.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

allowed_selinux_types := ["container_t", "container_init_t", "container_kvm_t"]

getAllSecurityContexts[context] {
	context := kubernetes.containers[_].securityContext
}

getAllSecurityContexts[context] {
	context := kubernetes.pods[_].spec.securityContext
}

failSELinuxType[type] {
	context := getAllSecurityContexts[_]

	trace(context.seLinuxOptions.type)
	context.seLinuxOptions != null
	context.seLinuxOptions.type != null

	not hasAllowedType(context.seLinuxOptions)

	type := context.seLinuxOptions.type
}

failForbiddenSELinuxProperties[key] {
	context := getAllSecurityContexts[_]

	context.seLinuxOptions != null

	forbiddenProps := getForbiddenSELinuxProperties(context)
	key := forbiddenProps[_]
}

getForbiddenSELinuxProperties(context) = keys {
	forbiddenProperties = ["role", "user"]
	keys := {msg |
		key := forbiddenProperties[_]
		utils.has_key(context.seLinuxOptions, key)
		msg := sprintf("'%s'", [key])
	}
}

hasAllowedType(options) {
	allowed_selinux_types[_] == options.type
}

deny[res] {
	type := failSELinuxType[_]

	msg := kubernetes.format(sprintf("%s '%s' uses invalid seLinux type '%s'", [kubernetes.kind, kubernetes.name, type]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

deny[res] {
	keys := failForbiddenSELinuxProperties

	count(keys) > 0

	msg := kubernetes.format(sprintf("%s '%s' uses restricted properties in seLinuxOptions: (%s)", [kubernetes.kind, kubernetes.name, concat(", ", keys)]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
