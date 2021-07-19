package appshield.dockerfile.DS002

exception[rules] {
	instruction := input.stages[_][_]
	instruction.Cmd == "label"

	key := instruction.Value[i]
	i % 2 == 0
	key == "user.root"

	value := instruction.Value[plus(i, 1)]
	value == "\"allow\""

	rules = [""]
}
