# METADATA
# schemas:
# - input: schema["dockerfile"]
package defsec.test_invalid

deny {
	input.Stages[0].Commands[0].FooBarNothingBurger == "lol"
}
