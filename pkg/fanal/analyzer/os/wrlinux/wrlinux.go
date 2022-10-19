/*
 * Copyright (c) 2022 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

package wrlinux

import (
	"bufio"
	"context"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&wrlinuxOSAnalyzer{})
}

const version = 1

var requiredFiles = []string{
	"usr/lib/os-release",
}

type wrlinuxOSAnalyzer struct{}

func (a wrlinuxOSAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	wrlinuxName := ""
	scanner := bufio.NewScanner(input.Content)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NAME=\"Wind River Linux") {
			wrlinuxName = aos.WRLinux
			continue
		}

		if wrlinuxName != "" && strings.HasPrefix(line, "VERSION_ID=") {
			return &analyzer.AnalysisResult{
				OS: &types.OS{
					Family: wrlinuxName,
					Name:   strings.TrimSpace(line[11:]),
				},
			}, nil
		}
	}
	return nil, xerrors.Errorf("wrlinux: %w", aos.AnalyzeOSError)
}

func (a wrlinuxOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a wrlinuxOSAnalyzer) Type() analyzer.Type {
	return analyzer.TypeWRLinux
}

func (a wrlinuxOSAnalyzer) Version() int {
	return version
}
