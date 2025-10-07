# METADATA
# title: Test rego 2
# description: Instances with userdata are not allowed
# schemas:
#   - input: schema["cloud"]
# custom:
#   avd_id: ID001
#   severity: MEDIUM
#   input:
#     selector: 
#     - type: cloud
#       subtypes:
#         - service: ec2
#           provider: aws
package user.aws.ID001

deny[res] {
    instance := input.aws.ec2.instances[_]
    instance.userdata.value != ""
    res := result.new("Instances with userdata are not allowed", instance.userdata)
}