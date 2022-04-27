package sum

import (
	"bufio"
	"io"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

// Parse parses a go.sum file
func Parse(r io.Reader) ([]types.Library, error) {
	var libs []types.Library
	uniqueLibs := make(map[string]string)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		s := strings.Fields(line)
		if len(s) < 2 {
			continue
		}

		// go.sum records and sorts all non-major versions
		// with the latest version as last entry
		uniqueLibs[s[0]] = strings.TrimSuffix(strings.TrimPrefix(s[1], "v"), "/go.mod")
	}
	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}

	for k, v := range uniqueLibs {
		libs = append(libs, types.Library{
			Name:    k,
			Version: v,
		})
	}

	return libs, nil
}
