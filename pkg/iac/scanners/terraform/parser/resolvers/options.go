package resolvers

import (
	"net/http"
	"strings"

	"github.com/aquasecurity/trivy/pkg/log"
)

type Options struct {
	Source, OriginalSource, Version, OriginalVersion, WorkingDir, Name, ModulePath string
	Logger                                                                         *log.Logger
	AllowDownloads                                                                 bool
	SkipCache                                                                      bool
	RelativePath                                                                   string
	CacheDir                                                                       string
	Client                                                                         *http.Client
}

func (o *Options) hasPrefix(prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(o.Source, prefix) {
			return true
		}
	}
	return false
}
