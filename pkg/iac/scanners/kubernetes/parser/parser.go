package parser

import (
	"bytes"
	"context"
	"io"
	"regexp"
	"strings"
)

func Parse(_ context.Context, r io.Reader, path string) ([]*Manifest, error) {
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
		return []*Manifest{manifest}, nil
	}

	var manifests []*Manifest

	re := regexp.MustCompile(`(?m:^---\r?\n)`)
	pos := 0
	for _, partial := range re.Split(string(contents), -1) {
		manifest, err := ManifestFromYAML(path, []byte(partial))
		if err != nil {
			return nil, err
		}
		if manifest.Content != nil {
			manifest.Content.Offset = pos
			manifests = append(manifests, manifest)
		}
		pos += len(strings.Split(partial, "\n"))
	}

	return manifests, nil
}
