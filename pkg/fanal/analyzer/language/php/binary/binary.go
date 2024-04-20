package generic

import (
	"context"
	"errors"
	"regexp"
	"fmt"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/php/binary"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/log"
)


func init() {
	analyzer.RegisterAnalyzer(&phpBinaryAnalyzer{})
}

const version = 1

type phpBinaryAnalyzer struct{}

func (a phpBinaryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.PhpGeneric, input.FilePath, input.Content, binary.NewParser())
	if errors.Is(err, binary.ErrUnrecognizedExe) {
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf("PHP binary parse error: %w", err)
	}
	log.Debug("result", fmt.Sprintf("%+v\n", res))
	return res, nil
}

func (a phpBinaryAnalyzer) Required(_ string, fileInfo os.FileInfo) bool {
	phpBinaryNameRegex := regexp.MustCompile("(.*/|^)php[0-9]*$")
	phpLibNameRegex := regexp.MustCompile("(.*/|^)libphp[0-9.-a-z]*[.]so$")
	phpFpmNameRegex := regexp.MustCompile("(.*/|^)php-fpm[0-9]*$")
	phpCgiNameRegex := regexp.MustCompile("(.*/|^)php-cgi[0-9]*$")

	isPHPBinary := phpBinaryNameRegex.FindSubmatch([]byte(fileInfo.Name()))
	isPHPLib := phpLibNameRegex.FindSubmatch([]byte(fileInfo.Name()))
	isPHPFpm := phpFpmNameRegex.FindSubmatch([]byte(fileInfo.Name()))
	isPHPCgi := phpCgiNameRegex.FindSubmatch([]byte(fileInfo.Name()))
	return utils.IsExecutable(fileInfo) && (isPHPBinary != nil || isPHPLib != nil || isPHPFpm != nil || isPHPCgi != nil)
}

func (a phpBinaryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePHPGeneric //Since we don't know the exact type of the binary and ecosystem, we need to use TypeGeneric which will query NVD for vulns
}

func (a phpBinaryAnalyzer) Version() int {
	return version
}