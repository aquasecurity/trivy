# METADATA
# title: Test check
# schemas:
# - input: schema.test
# custom:
#   id: TEST001
#   severity: LOW
package user.test_yaml_check

deny[res] {
    input.wrong_ref == "foo"
    res := result.new(`Service "foo" should not be used`, input.service)
}