# METADATA
# schemas:
# - input: schema["fooschema"]

package builtin.bad.test

deny {
    input.evil == "foo bar"
}