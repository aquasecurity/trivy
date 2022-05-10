package resolvers

import (
	"fmt"
	"io"
	"strings"
)

type Options struct {
	Source, OriginalSource, Version, OriginalVersion, WorkingDir, Name, ModulePath string
	DebugWriter                                                                    io.Writer
	AllowDownloads                                                                 bool
	AllowCache                                                                     bool
}

func (o *Options) hasPrefix(prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(o.Source, prefix) {
			return true
		}
	}
	return false
}

func (o *Options) Debug(format string, args ...interface{}) {
	if o.DebugWriter == nil {
		return
	}
	_, _ = o.DebugWriter.Write([]byte("[module:retrieve] " + fmt.Sprintf(format, args...) + "\n"))
}
