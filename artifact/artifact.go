package artifact

import (
	"context"
	"sort"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/types"
)

type Option struct {
	DisabledAnalyzers []analyzer.Type
	DisabledHooks     []hook.Type
	SkipFiles         []string
	SkipDirs          []string
}

func (o *Option) Sort() {
	sort.Slice(o.DisabledAnalyzers, func(i, j int) bool {
		return o.DisabledAnalyzers[i] < o.DisabledAnalyzers[j]
	})
	sort.Strings(o.SkipFiles)
	sort.Strings(o.SkipDirs)
}

type Artifact interface {
	Inspect(ctx context.Context) (reference types.ArtifactReference, err error)
}
