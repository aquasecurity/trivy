package starboard.policy.k8s.custom

__rego_metadata__ := {
	"id": "recommended_labels",
	"title": "Recommended labels",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "A common set of labels allows tools to work interoperably, describing objects in a common manner that all tools can understand.",
	"recommended_actions": "Take full advantage of using recommended labels and apply them on every resource object.",
	"url": "https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/",
}

recommended_labels := [
	"app.kubernetes.io/name",
	"app.kubernetes.io/version",
]

deny[res] {
	provided := {label | input.metadata.labels[label]}
	required := {label | label := recommended_labels[_]}
	missing := required - provided
	count(missing) > 0
	msg := sprintf("You must provide labels: %v", [missing])
	res := {"msg": msg}
}
