# METADATA
# schemas:
# - input: schema["input"]
package defsec.test_invalid

deny {
	input.Stages[0].Commands[0].FooBarNothingBurger == "lol"
}
