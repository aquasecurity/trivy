// Ported from https://github.com/golang/go/blob/e9c96835971044aa4ace37c7787de231bbde05d9/src/cmd/go/internal/version/version.go

package binary

import (
	"bytes"
	"io"
	"regexp"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

// Parse scans file to try to report the NodeJS version.
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

// findVers finds and returns the NodeJS version in the executable x.
func findVers(x exe) (vers, mod string) {
	text, size := x.DataStart()
	data, err := x.ReadData(text, size)
	if err != nil {
		return
	}

	re := regexp.MustCompile(`node\.js\/v(\d{1,3}\.\d{1,3}\.\d{1,3})`)
	// split by null characters
	items := bytes.Split(data, []byte("\000"))
	for _, s := range items {
		// Extract the version number
		match := re.FindSubmatch(s)
		if match != nil {
			vers = string(match[1])
			break
		}
	}

	return vers, "node.js"
}
