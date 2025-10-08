package functions

import "fmt"

// Reference function can't work as per Azure because it requires Azure ARM logic
// best effort is to return the resourcename with a suffix to try and make it unique
func Reference(args ...any) any {
	if len(args) < 1 {
		return nil
	}
	return fmt.Sprintf("%v-reference", args[0])
}
