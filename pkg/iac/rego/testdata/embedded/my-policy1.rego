# METADATA
# schemas:
# - input: schema["fooschema"]

package builtin.test

deny {
    input.foo == "foo bar"
}