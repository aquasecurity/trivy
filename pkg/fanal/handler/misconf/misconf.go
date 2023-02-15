package misconf

import (
	"context"
	_ "embed"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/misconf"
)

func init() {
	handler.RegisterPostHandlerInit(types.MisconfPostHandler, newMisconfPostHandler)
}

const version = 1

type misconfPostHandler struct {
	scanner misconf.Scanner
}

func newMisconfPostHandler(artifactOpt artifact.Option) (handler.PostHandler, error) {
	s, err := misconf.NewScanner(artifactOpt.FilePatterns, artifactOpt.MisconfScannerOption)
	if err != nil {
		return nil, xerrors.Errorf("scanner init error: %w", err)
	}
	return misconfPostHandler{
		scanner: s,
	}, nil
}

// Handle detects misconfigurations.
func (h misconfPostHandler) Handle(ctx context.Context, result *analyzer.AnalysisResult, blob *types.BlobInfo) error {
	files, ok := result.Files[h.Type()]
	if !ok {
		return nil
	}

	misconfs, err := h.scanner.Scan(ctx, files)
	if err != nil {
		return xerrors.Errorf("misconfiguration scan error: %w", err)
	}

	blob.Misconfigurations = misconfs

	return nil
}

func (h misconfPostHandler) Version() int {
	return version
}

func (h misconfPostHandler) Type() types.HandlerType {
	return types.MisconfPostHandler
}

func (h misconfPostHandler) Priority() int {
	return types.MisconfPostHandlerPriority
}
