# METADATA
# title: Test rego
# description: A bucket named "test-bucket" is not allowed
# schemas:
#   - input: schema["cloud"]
# custom:
#   avd_id: ID001
#   severity: LOW
#   input:
#     selector: 
#     - type: cloud
#       subtypes:
#         - service: s3
#           provider: aws
package user.aws.ID001

deny[res] {
    bucket := input.aws.s3.buckets[_]
    bucket.name.value == "test-bucket"
    res := result.new("Bucket not allowed", bucket.name)
}