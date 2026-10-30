package node

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

const (
	version      = 2
	requiredFile = "node_version.h"
)

func init() {
	analyzer.RegisterAnalyzer(&nodeAnalyzer{})
}

type parser struct{}

func (parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]types.Package, []types.Dependency, error) {
	var versions [3]int
	var found [3]bool
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || fields[0] != "#define" {
			continue
		}
		var i int
		switch fields[1] {
		case "NODE_MAJOR_VERSION":
			i = 0
		case "NODE_MINOR_VERSION":
			i = 1
		case "NODE_PATCH_VERSION":
			i = 2
		default:
			continue
		}
		v, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, nil, err
		}
		versions[i], found[i] = v, true
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	if !found[0] || !found[1] || !found[2] {
		return nil, nil, nil
	}
	ver := fmt.Sprintf("%d.%d.%d", versions[0], versions[1], versions[2])
	return []types.Package{{
		ID:      dependency.ID(types.Node, "node", ver),
		Name:    "node",
		Version: ver,
	}}, nil, nil
}

type nodeAnalyzer struct{}

func (nodeAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	var p language.Parser = parser{}
	if filepath.Base(input.FilePath) != requiredFile {
		p = binaryParser{}
	}
	return language.AnalyzePackage(ctx, types.Node, input.FilePath, input.Content, p, input.Options.FileChecksum)
}

func (nodeAnalyzer) Required(filePath string, info os.FileInfo) bool {
	if strings.HasSuffix(filepath.ToSlash(filePath), "include/node/"+requiredFile) {
		return true
	}
	name := filepath.Base(filePath)
	return (name == "node" || name == "nodejs") && info != nil && info.Mode().IsRegular() && utils.IsExecutable(info)
}

func (nodeAnalyzer) Type() analyzer.Type { return analyzer.TypeNode }

func (nodeAnalyzer) Version() int { return version }
