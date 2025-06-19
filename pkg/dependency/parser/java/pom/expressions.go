package pom

import (
	"os"
	"regexp"
	"slices"
	"strings"
)

var varRegexp = regexp.MustCompile(`\${(\S+?)}`)

func isProperty(s string) bool {
	if s != "" && strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") {
		return true
	}
	return false
}

func evaluateVariable(s string, props map[string]string, seenProps []string) string {
	if props == nil {
		props = make(map[string]string)
	}

	for _, m := range varRegexp.FindAllStringSubmatch(s, -1) {
		var newValue string

		// env.X: https://maven.apache.org/pom.html#Properties
		// e.g. env.PATH
		if strings.HasPrefix(m[1], "env.") {
			newValue = os.Getenv(strings.TrimPrefix(m[1], "env."))
		} else {
			// <properties> might include another property.
			// e.g. <animal.sniffer.skip>${skipTests}</animal.sniffer.skip>
			ss, ok := props[m[1]]
			if ok {
				// search for looped properties
				if slices.Contains(seenProps, ss) {
					printLoopedPropertiesStack(m[0], seenProps)
					return ""
				}
				seenProps = append(seenProps, ss) // save evaluated props to check if we get this prop again
				newValue = evaluateVariable(ss, props, seenProps)
				seenProps = []string{} // clear props if we returned from recursive. Required for correct work with 2 same props like ${foo}-${foo}
			}

		}
		s = strings.ReplaceAll(s, m[0], newValue)
	}
	return strings.TrimSpace(s)
}
