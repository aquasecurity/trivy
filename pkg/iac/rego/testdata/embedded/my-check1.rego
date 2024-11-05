# METADATA
# schemas:
# - input: schema["fooschema"]
# custom:
#   avd_id: test-001

package builtin.test

deny {
    input.foo == "foo bar"
}