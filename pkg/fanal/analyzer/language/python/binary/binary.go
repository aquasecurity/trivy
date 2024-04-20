package generic

import (
	"context"
	"errors"
	"regexp"
	"fmt"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/binary"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/log"
)


func init() {
	analyzer.RegisterAnalyzer(&pythonBinaryAnalyzer{})
}

const version = 1

type pythonBinaryAnalyzer struct{}

func (a pythonBinaryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.PythonGeneric, input.FilePath, input.Content, binary.NewParser())
	if errors.Is(err, binary.ErrUnrecognizedExe) || errors.Is(err, binary.ErrNonPythonBinary) {
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf("Python binary parse error: %w", err)
	}
	log.Debug("result", fmt.Sprintf("%+v\n", res))
	return res, nil
}

func (a pythonBinaryAnalyzer) Required(_ string, fileInfo os.FileInfo) bool {
	pythonLibNameRegex := regexp.MustCompile("^libpython[0-9]+(?:[.0-9]+)+[a-z]?[.]so.*$")
	pythonBinaryNameRegex := regexp.MustCompile("(?:.*/|^)python(?P<version>[0-9]+(?:[.0-9]+)+)?$")
	isPythonBinary := pythonBinaryNameRegex.FindSubmatch([]byte(fileInfo.Name()))
	isPythonLibSo := pythonLibNameRegex.FindSubmatch([]byte(fileInfo.Name()))
	return utils.IsExecutable(fileInfo) && (isPythonBinary != nil || isPythonLibSo != nil)
}

func (a pythonBinaryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePythonGeneric //Since we don't know the exact type of the binary and ecosystem, we need to use TypeGeneric which will query NVD for vulns
}

func (a pythonBinaryAnalyzer) Version() int {
	return version
}
