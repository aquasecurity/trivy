# METADATA
# title: "Bad stuff is bad"
# description: "Its not good!"
# scope: package
# schemas:
# - input: schema["cloud"]
# custom:
#   avd_id: AVD-TEST-0001
#   id: TEST001
#   provider: aws
#   service: sqs
#   severity: HIGH
#   short_code: foo-bar-baz
#   recommended_action: "Remove bad stuff"
#   input:
#     selector:
#     - type: cloud
package user.something

deny[res] {
    qs := input.aws.sqs.queues[_]
    qs.encryption.kmskeyid.value == ""
    res := "No unencrypted queues allowed!"
}