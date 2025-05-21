# METADATA
# title: Custom policy
# description: Custom policy for testing
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   id: AVD-BAR-0001
#   avd_id: AVD-BAR-0001
#   provider: custom
#   service: custom
#   severity: LOW
#   short_code: custom-policy
#   recommended_action: Custom policy for testing
package user.bar

deny[res] {
	res := "something bad: bar"
}
