# METADATA
# schemas:
# - input: schema["fooschema"]
# custom:
#   id: test-001
#   avd_id: avd-test-001
package builtin.test

deny {
    input.foo == "foo bar"
}