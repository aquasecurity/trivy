package artifact

import (
	"context"
	"sort"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	misconf "github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/licensing"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type Option struct {
	AnalyzerGroup     analyzer.Group // It is empty in OSS
	DisabledAnalyzers []analyzer.Type
	DisabledHandlers  []types.HandlerType
	SkipFiles         []string
	SkipDirs          []string
	NoProgress        bool
	Offline           bool
	InsecureSkipTLS   bool
	AppDirs           []string

	MisconfScannerOption   misconf.ScannerOption
	SecretScannerOption    secret.ScannerOption
	LicensingScannerOption licensing.ScannerOption
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
	Clean(reference types.ArtifactReference) error
}
