# METADATA
# schemas:
# - input: schema["dockerfile"]
package defsec.test_valid

deny {
	input.Stages[0].Commands[0].Cmd == "lol"
}
