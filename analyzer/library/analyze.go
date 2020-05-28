package library

import (
	"bytes"
	"io"

	"github.com/aquasecurity/fanal/analyzer"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

func Analyze(content []byte, parse func(r io.Reader) ([]godeptypes.Library, error)) (analyzer.AnalyzeReturn, error) {
	r := bytes.NewBuffer(content)
	libs, err := parse(r)
	if err != nil {
		return analyzer.AnalyzeReturn{}, xerrors.Errorf("error with a lock file: %w", err)
	}
	return analyzer.AnalyzeReturn{
		Libraries: libs,
	}, nil
}
