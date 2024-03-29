package parser

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/strvals"
)

type ValueOptions struct {
	ValueFiles   []string
	StringValues []string
	Values       []string
	FileValues   []string
}

// MergeValues merges values from files specified via -f/--values and directly
// via --set, --set-string, or --set-file, marshaling them to YAML
func (opts *ValueOptions) MergeValues() (map[string]interface{}, error) {
	base := make(map[string]interface{})

	// User specified a values files via -f/--values
	for _, filePath := range opts.ValueFiles {
		currentMap := make(map[string]interface{})

		bytes, err := readFile(filePath)
		if err != nil {
			return nil, err
		}

		if err := yaml.Unmarshal(bytes, &currentMap); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", filePath, err)
		}
		// Merge with the previous map
		base = mergeMaps(base, currentMap)
	}

	// User specified a value via --set
	for _, value := range opts.Values {
		if err := strvals.ParseInto(value, base); err != nil {
			return nil, fmt.Errorf("failed parsing --set data, %w", err)
		}
	}

	// User specified a value via --set-string
	for _, value := range opts.StringValues {
		if err := strvals.ParseIntoString(value, base); err != nil {
			return nil, fmt.Errorf("failed parsing --set-string data %w", err)
		}
	}

	// User specified a value via --set-file
	for _, value := range opts.FileValues {
		reader := func(rs []rune) (interface{}, error) {
			bytes, err := readFile(string(rs))
			if err != nil {
				return nil, err
			}
			return string(bytes), err
		}
		if err := strvals.ParseIntoFile(value, base, reader); err != nil {
			return nil, fmt.Errorf("failed parsing --set-file data: %w", err)
		}
	}

	return base, nil
}

func mergeMaps(a, b map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(a))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if v, ok := v.(map[string]interface{}); ok {
			if bv, ok := out[k]; ok {
				if bv, ok := bv.(map[string]interface{}); ok {
					out[k] = mergeMaps(bv, v)
					continue
				}
			}
		}
		out[k] = v
	}
	return out
}

// readFile load a file from stdin, the local directory, or a remote file with a url.
func readFile(filePath string) ([]byte, error) {
	if strings.TrimSpace(filePath) == "-" {
		return io.ReadAll(os.Stdin)
	}
	u, _ := url.Parse(filePath)

	// FIXME: maybe someone handle other protocols like ftp.
	if u.Scheme == "http" || u.Scheme == "https" {
		g, err := getter.NewHTTPGetter()
		if err != nil {
			return nil, err
		}
		data, err := g.Get(filePath, getter.WithURL(filePath))
		if err != nil {
			return nil, err
		}
		return data.Bytes(), err
	} else {
		return os.ReadFile(filePath)
	}
}
