package functions

import (
	"net/url"
	"path"
)

func Uri(args ...any) any {
	if len(args) != 2 {
		return ""
	}

	result, err := joinPath(args[0].(string), args[1].(string))
	if err != nil {
		return ""
	}
	return result
}

// Backport url.JoinPath until we're ready for Go 1.19
func joinPath(base string, elem ...string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	elem = append([]string{u.EscapedPath()}, elem...)
	u.Path = path.Join(elem...)
	return u.String(), nil
}
