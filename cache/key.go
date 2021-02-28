package cache

import (
	"fmt"
	"strings"
)

const keySeparator = "/"

func WithVersionSuffix(key, version string) string {
	// e.g. sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e
	//   => sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e/11201101
	return fmt.Sprintf("%s%s%s", key, keySeparator, version)
}

func TrimVersionSuffix(versioned string) string {
	// e.g.sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e/11201101
	//  => sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e
	ss := strings.Split(versioned, keySeparator)
	if len(ss) < 2 {
		return versioned
	}
	return ss[0]
}
