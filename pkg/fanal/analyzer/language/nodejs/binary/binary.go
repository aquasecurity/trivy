package generic

import (
	"context"
	"errors"
	"regexp"
	"fmt"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/binary"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/log"
)


func init() {
	analyzer.RegisterAnalyzer(&nodejsBinaryAnalyzer{})
}

const version = 1

type nodejsBinaryAnalyzer struct{}

func (a nodejsBinaryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.NodeJsGeneric, input.FilePath, input.Content, binary.NewParser())
	if errors.Is(err, binary.ErrUnrecognizedExe) {
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf("NodeJS binary parse error: %w", err)
	}
	log.Debug("result", fmt.Sprintf("%+v\n", res))
	return res, nil
}

func (a nodejsBinaryAnalyzer) Required(_ string, fileInfo os.FileInfo) bool {
	nodejsBinaryNameRegex := regexp.MustCompile("(?:.*/|^)node(?P<version>[0-9]+(?:[.0-9]+)+)?$")
	isNodeJsBinary := nodejsBinaryNameRegex.FindSubmatch([]byte(fileInfo.Name()))
	return utils.IsExecutable(fileInfo) && (isNodeJsBinary != nil)
}

func (a nodejsBinaryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeNodeJsGeneric //Since we don't know the exact type of the binary and ecosystem, we need to use TypeGeneric which will query NVD for vulns
}

func (a nodejsBinaryAnalyzer) Version() int {
	return version
}
