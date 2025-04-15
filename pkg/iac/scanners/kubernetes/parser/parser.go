package parser

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
)

func Parse(_ context.Context, r io.Reader, path string) ([]any, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if len(contents) == 0 {
		return nil, nil
	}

	if bytes.TrimSpace(contents)[0] == '{' {
		manifest, err := ManifestFromJSON(path, contents)
		if err != nil {
			return nil, err
		}
		return []any{manifest.ToRego()}, nil
	}

	var results []any

	re := regexp.MustCompile(`(?m:^---\r?\n)`)
	offset := 0
	for _, partial := range re.Split(string(contents), -1) {
		manifest, err := ManifestFromYAML(path, []byte(partial), offset)
		if err != nil {
			return nil, fmt.Errorf("unmarshal yaml: %w", err)
		}
		if err := manifest.Validate(); err != nil {
			return nil, fmt.Errorf("manifest is invalid: %w", err)
		}
		if !manifest.IsEmpty() {
			results = append(results, manifest.ToRego())
		}
		offset += len(strings.Split(partial, "\n"))
	}

	return results, nil
}
