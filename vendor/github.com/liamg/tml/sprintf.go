package tml

import "fmt"

// Sprintf works like fmt.Sprintf, but adds the option of using tags to apply colour or text formatting to the written text. For example "<red>some red text</red>".
// A full list of tags is available here: https://github.com/liamg/tml
func Sprintf(input string, a ...interface{}) string {
	// parsing cannot fail as the reader/writer are simply for local strings
	format, _ := Parse(input)
	return fmt.Sprintf(format, a...)
}
