package secret

import (
	"context"
	"encoding/json"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/secret"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

const analyzerVersion = 1

func init() {
	analyzer.RegisterConfigAnalyzer(analyzer.TypeImageConfigSecret, newSecretAnalyzer)
}

// secretAnalyzer detects secrets in container image config.
type secretAnalyzer struct {
	scanner secret.Scanner
}

func newSecretAnalyzer(opts analyzer.ConfigAnalyzerOptions) (analyzer.ConfigAnalyzer, error) {
	configPath := opts.SecretScannerOption.ConfigPath
	c, err := secret.ParseConfig(configPath)
	if err != nil {
		return nil, xerrors.Errorf("secret config error: %w", err)
	}
	scanner := secret.NewScanner(c)

	return &secretAnalyzer{
		scanner: scanner,
	}, nil
}

func (a *secretAnalyzer) Analyze(_ context.Context, input analyzer.ConfigAnalysisInput) (*analyzer.
	ConfigAnalysisResult, error) {
	if input.Config == nil {
		return nil, nil
	}
	b, err := json.MarshalIndent(input.Config, "  ", "")
	if err != nil {
		return nil, xerrors.Errorf("json marshal error: %w", err)
	}

	result := a.scanner.Scan(secret.ScanArgs{
		FilePath: "config.json",
		Content:  b,
	})

	if len(result.Findings) == 0 {
		log.Logger.Debug("No secrets found in container image config")
		return nil, nil
	}

	return &analyzer.ConfigAnalysisResult{
		Secret: &result,
	}, nil
}

func (a *secretAnalyzer) Required(_ types.OS) bool {
	return true
}

func (a *secretAnalyzer) Type() analyzer.Type {
	return analyzer.TypeImageConfigSecret
}

func (a *secretAnalyzer) Version() int {
	return analyzerVersion
}
