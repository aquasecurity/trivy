package functions

var loopCounter = make(map[string]int)

func CopyIndex(args ...interface{}) interface{} {
	loopName := "default"
	offset := 1
	if len(args) > 0 {
		if providedLoopName, ok := args[0].(string); ok {
			loopName = providedLoopName
		}
	}
	if len(args) > 1 {
		if providedOffset, ok := args[1].(int); ok {
			offset = providedOffset
		}
	}

	if _, ok := loopCounter[loopName]; !ok {
		loopCounter[loopName] = 0
	}

	loopCounter[loopName] += offset
	return loopCounter[loopName]
}
