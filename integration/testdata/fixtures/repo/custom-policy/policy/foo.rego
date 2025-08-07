# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: FOO-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   long_id: custom-policy
#   recommended_action: Custom policy for testing
package user.foo

deny[res] {
	res := "something bad: foo"
}
