# METADATA
# title: Test policy
# description: This is a test policy.
# schemas:
#   - input: schema["my-docker-schema"]
# custom:
#   id: TEST001
#   avd_id: AVD-TEST-0001
#   severity: LOW
#   short_code: no-buckets
#   recommended_actions: Have a cup of tea.
#   url: https://trivy.dev/
package user.something

# taken from defsec rego lib to mimic behaviour
result(msg, cause) = result {
	metadata := object.get(cause, "__defsec_metadata", cause)
	result := {
		"msg": msg,
		"startline": object.get(metadata, "startline", object.get(metadata, "StartLine", 0)),
		"endline": object.get(metadata, "endline", object.get(metadata, "EndLine", 0)),
		"filepath": object.get(metadata, "filepath", object.get(metadata, "Path", "")),
		"explicit": object.get(metadata, "explicit", false),
		"managed": object.get(metadata, "managed", true),
		"fskey": object.get(metadata, "fskey", ""),
		"resource": object.get(metadata, "resource", ""),
	}
}

deny[res] {
	cmd := input.Stages[_].Commands[_]
	cmd.Original == "FROM alpine"
	res := result("No commands allowed!", cmd)
}
