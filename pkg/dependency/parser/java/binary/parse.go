// Ported from https://github.com/golang/go/blob/e9c96835971044aa4ace37c7787de231bbde05d9/src/cmd/go/internal/version/version.go

package javabinary

import (
	"bytes"
	"io"
	"regexp"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

// Parse scans file to try to report the OpenJDK version.
func Parse(r io.Reader) ([]types.Library, error) {
	x, err := openExe(r)
	if err != nil {
		return nil, err
	}

	vers, mod := findVers(x)
	if vers == "" {
		return nil, nil
	}

	var libs []types.Library
	libs = append(libs, types.Library{
		Name:    mod,
		Version: vers,
	})

	return libs, nil
}

// findVers finds and returns the Java version in the executable x.
func findVers(x exe) (vers string, mod string) {
	text, size := x.DataStart()
	data, err := x.ReadData(text, size)
	if err != nil {
		return
	}

	re := regexp.MustCompile(`\d{1,4}\.\d{1,4}\.\d{1,4}`)
	// split by null characters
	items := bytes.Split(data, []byte("\000"))
	for _, s := range items {
		// If the string starts with a version number
		if re.Match(s) {
			vers = string(s)
		} else if strings.Contains(string(s), "openjdk") {
			mod = "openjdk"
		}
	}

	if mod == "openjdk" {
		return vers, mod
	}
	return
}