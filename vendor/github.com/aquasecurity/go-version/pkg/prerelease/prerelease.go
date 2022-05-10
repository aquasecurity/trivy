package prerelease

import (
	"reflect"

	"github.com/aquasecurity/go-version/pkg/part"
)

func Compare(p1, p2 part.Parts) int {
	switch {
	case reflect.DeepEqual(p1, p2):
		return 0
	case p1.IsAny() || p2.IsAny():
		return 0
	case p1.IsNull():
		return 1
	case p2.IsNull():
		return -1
	}

	return p1.Compare(p2)
}
