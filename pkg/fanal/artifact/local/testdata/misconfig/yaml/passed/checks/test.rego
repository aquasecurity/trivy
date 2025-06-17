# METADATA
# title: Test check
# custom:
#   avd_id: AVD-TEST-0001
#   severity: LOW
package user.test_yaml_check

deny[res] {
    input.service == "foo"
    res := result.new(`Service "foo" should not be used`, input.service)
}

deny[res] {
    input.provider == "bar"
    res := result.new(`Provider "bar" should not be used`, input.provider)
}