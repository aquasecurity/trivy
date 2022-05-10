// +build gofuzz

package ast

func Fuzz(data []byte) int {

	str := string(data)
	_, _, err := ParseStatements("", str)

	if err == nil {
		CompileModules(map[string]string{"": str})
		return 1
	}

	return 0
}
