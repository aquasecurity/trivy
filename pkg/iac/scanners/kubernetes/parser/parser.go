package parser

import (
	"bytes"
	"context"
	"io"
	"regexp"
	"strings"
)

var separatorRegex = regexp.MustCompile(`(?m:^---\r?\n)`)

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

	offset := 0
	for i, partial := range separatorRegex.Split(string(contents), -1) {
		if i > 0 {
			// The separator line is dropped by the split.
			offset++
		}

		manifest, err := ManifestFromYAML(path, []byte(partial))
		if err != nil {
			return nil, err
		}
		if manifest.Content != nil {
			// Each document is parsed on its own, so its lines are counted from the
			// start of the document. Shift them to point at the place in the file.
			manifest.Content.Walk(func(n *ManifestNode) {
				n.StartLine += offset
				n.EndLine += offset
			})
			manifests = append(manifests, manifest)
		}

		offset += countLines(partial)
	}

	return manifests, nil
}

func countLines(s string) int {
	if s == "" {
		return 0
	}

	count := strings.Count(s, "\n")
	if s[len(s)-1] != '\n' {
		count++
	}
	return count
}
