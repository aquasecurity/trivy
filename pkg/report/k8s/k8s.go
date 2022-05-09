package k8s

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Writer interface {
	Write(types.K8sReport) error
}

func Write(report types.K8sReport, option report.Option) error {
	var writer Writer
	switch option.Format {
	case "json":
		writer = &JSONWriter{Output: option.Output}
	default:
		return xerrors.Errorf("unknown format: %v", option.Format)
	}

	return writer.Write(report)
}
