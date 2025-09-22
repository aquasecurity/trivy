# METADATA
# title: Test policy
# schemas:
# - input: schema["terraform-raw"]
# custom:
#   id: TEST-0002
#   long_id: empty-bucket-name
#   severity: LOW
#   input:
#     selector:
#     - type: terraform-raw
package user.test002

import rego.v1

deny contains res if {
	some block in input.modules[_].blocks
	block.kind == "resource"
	block.type == "aws_s3_bucket"
	not "bucket" in block.attributes
	res := result.new("Empty bucket name!", block)
}
