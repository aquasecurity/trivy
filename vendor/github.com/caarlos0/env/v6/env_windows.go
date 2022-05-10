package env

import "strings"

func toMap(env []string) map[string]string {
	r := map[string]string{}
	for _, e := range env {
		p := strings.SplitN(e, "=", 2)

		// On Windows, environment variables can start with '='. If so, Split at next character.
		// See env_windows.go in the Go source: https://github.com/golang/go/blob/master/src/syscall/env_windows.go#L58
		prefixEqualSign := false
		if len(e) > 0 && e[0] == '=' {
			e = e[1:]
			prefixEqualSign = true
		}
		p = strings.SplitN(e, "=", 2)
		if prefixEqualSign {
			p[0] = "=" + p[0]
		}

		r[p[0]] = p[1]
	}
	return r
}
