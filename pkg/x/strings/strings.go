package strings

import (
	"fmt"

	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

type String interface {
	~string
}

func ToStringSlice[T any](ss []T) []string {
	if len(ss) == 0 {
		return nil
	}
	return xslices.Map(ss, func(s T) string {
		switch v := any(s).(type) {
		case string:
			return v
		case fmt.Stringer:
			return v.String()
		default:
			return fmt.Sprint(v)
		}
	})
}

func ToTSlice[T String](ss []string) []T {
	if ss == nil {
		return nil
	}
	return xslices.Map(ss, func(s string) T {
		return T(s)
	})
}
