# METADATA
# title: Test policy
# description: This is a test policy.
# related_resources:
# - "https://trivy.dev/"
# custom:
#   id: AVD-TEST-0001
#   severity: LOW
#   short_code: no-buckets
#   recommended_actions: Have a cup of tea.
#   input:
#     selector:
#     - type: kubernetes
package user.something

# taken from defsec rego lib to mimic behaviour
result(msg, cause) = result {
	metadata := object.get(cause, "__defsec_metadata", cause)
	result := {
		"msg": msg,
		"startline": object.get(metadata, "startline", 0),
		"endline": object.get(metadata, "endline", 0),
		"filepath": object.get(metadata, "filepath", ""),
		"explicit": object.get(metadata, "explicit", false),
		"managed": object.get(metadata, "managed", true),
		"fskey": object.get(metadata, "fskey", ""),
		"resource": object.get(metadata, "resource", ""),
	}
}

deny[res] {
    container := input.spec.containers[_]
    container.image == "evil"
    res := result("No evil containers allowed!", container)
}