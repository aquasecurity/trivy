package extension

import (
	"sort"

	"github.com/samber/lo"
)

var extensions = make(map[string]Extension)

type Extension interface {
	// Name returns the name of the extension.
	Name() string
}

func Register(s Extension) {
	// Avoid duplication
	extensions[s.Name()] = s
}

func Deregister(name string) {
	delete(extensions, name)
}

func Extensions() []Extension {
	exts := lo.Values(extensions)
	sort.Slice(exts, func(i, j int) bool {
		return exts[i].Name() < exts[j].Name()
	})
	return exts
}
