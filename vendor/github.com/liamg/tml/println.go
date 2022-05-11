package tml

import (
	"io"
	"os"
)

// Println works like fmt.Println, but adds the option of using tags to apply colour or text formatting to the written text. For example "<red>some red text</red>".
// A full list of tags is available here: https://github.com/liamg/tml
func Println(input string) {
	Fprintln(os.Stdout, input)
}

func Fprintln(w io.Writer, input string) {
	Fprintf(w, "%s\n", input)
}
