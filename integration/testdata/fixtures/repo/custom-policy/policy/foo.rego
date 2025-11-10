# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-FOO-0001
#   avd_id: AVD-FOO-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing
package user.foo

deny[res] {
	res := "something bad: foo"
}
