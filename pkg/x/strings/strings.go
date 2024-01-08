package strings

import "github.com/samber/lo"

type String interface {
	~string
}

func ToStringSlice[T String](ss []T) []string {
	return lo.Map(ss, func(s T, _ int) string {
		return string(s)
	})
}

func ToTSlice[T String](ss []string) []T {
	return lo.Map(ss, func(s string, _ int) T {
		return T(s)
	})
}
