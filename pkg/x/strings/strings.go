package strings

import (
	"fmt"

	"github.com/samber/lo"
)

type String interface {
	~string
}

func ToStringSlice[T any](ss []T) []string {
	if len(ss) == 0 {
		return nil
	}
	return lo.Map(ss, func(s T, _ int) string {
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
	return lo.Map(ss, func(s string, _ int) T {
		return T(s)
	})
}
