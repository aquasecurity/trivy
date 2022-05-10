package tml

import (
	"strings"
	"bytes"
)

// Parse converts the input string (containing TML tags) into a string containing ANSI escape code sequences for output to the terminal.
func Parse(input string) (string, error) {
	output := bytes.NewBufferString("")
	if err := NewParser(output).Parse(strings.NewReader(input)); err != nil {
		return "", err
	}
	return output.String(), nil
}
