package parser

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

func Parse(_ context.Context, r io.Reader, path string) ([]any, error) {
	contents, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if len(contents) == 0 {
		return nil, nil
	}

	if strings.TrimSpace(string(contents))[0] == '{' {
		manifest, err := ManifestFromJSON(path, contents)
		if err != nil {
			return nil, err
		}
		return []any{manifest.ToRego()}, nil
	}

	var results []any

	re := regexp.MustCompile(`(?m:^---\r?\n)`)
	pos := 0
	for _, partial := range re.Split(string(contents), -1) {
		var result Manifest
		result.Path = path
		if err := yaml.Unmarshal([]byte(partial), &result); err != nil {
			return nil, fmt.Errorf("unmarshal yaml: %w", err)
		}
		if result.Content != nil {
			result.Content.Offset = pos
			results = append(results, result.ToRego())
		}
		pos += len(strings.Split(partial, "\n"))
	}

	return results, nil
}
