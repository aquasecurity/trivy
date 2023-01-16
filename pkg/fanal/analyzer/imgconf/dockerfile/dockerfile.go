package apk

import (
	"bytes"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

const analyzerVersion = 1

func init() {
	analyzer.RegisterConfigAnalyzer(&historyAnalyzer{})
}

type historyAnalyzer struct{}

func (a historyAnalyzer) Analyze(input analyzer.ConfigAnalysisInput) (*analyzer.AnalysisResult, error) {
	if input.Config == nil {
		return nil, nil
	}
	dockerfile := new(bytes.Buffer)
	for _, h := range input.Config.History {
		var createdBy string
		switch {
		case strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop)"):
			// Instruction other than RUN
			createdBy = strings.TrimPrefix(h.CreatedBy, "/bin/sh -c #(nop)")
		case strings.HasPrefix(h.CreatedBy, "/bin/sh -c"):
			// RUN instruction
			createdBy = strings.ReplaceAll(h.CreatedBy, "/bin/sh -c", "RUN")
		}
		dockerfile.WriteString(strings.TrimSpace(createdBy) + "\n")
	}

	return &analyzer.AnalysisResult{
		Files: map[types.HandlerType][]types.File{
			types.MisconfPostHandler: {
				{
					Type:    types.Dockerfile,
					Path:    "Dockerfile",
					Content: dockerfile.Bytes(),
				},
			},
		},
	}, nil
}

func (a historyAnalyzer) Required(_ types.OS) bool {
	return true
}

func (a historyAnalyzer) Type() analyzer.Type {
	return analyzer.TypeHistoryDockerfile
}

func (a historyAnalyzer) Version() int {
	return analyzerVersion
}
