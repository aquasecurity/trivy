package secret

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/secret"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/log"
)

// To make sure SecretAnalyzer implements analyzer.Initializer
var _ analyzer.Initializer = &SecretAnalyzer{}

const version = 1

var allowedBinaries = []string{
	".pyc",
}

func init() {
	// The scanner will be initialized later via InitScanner()
	analyzer.RegisterAnalyzer(NewSecretAnalyzer(secret.Scanner{}, ""))
}

func allowedBinary(filename string) bool {
	return slices.Contains(allowedBinaries, filepath.Ext(filename))
}

// SecretAnalyzer is an analyzer for secrets
type SecretAnalyzer struct {
	scanner    secret.Scanner
	configPath string
}

func NewSecretAnalyzer(s secret.Scanner, configPath string) *SecretAnalyzer {
	return &SecretAnalyzer{
		scanner:    s,
		configPath: cleanPath(configPath),
	}
}

// Init initializes and sets a secret scanner
func (a *SecretAnalyzer) Init(opt analyzer.AnalyzerOptions) error {
	configPath := cleanPath(opt.SecretScannerOption.ConfigPath)
	if configPath == a.configPath && !lo.IsEmpty(a.scanner) {
		// This check is for tools importing Trivy and customize analyzers
		// Never reach here in Trivy OSS
		return nil
	}
	c, err := secret.ParseConfig(configPath)
	if err != nil {
		return xerrors.Errorf("secret config error: %w", err)
	}
	a.scanner = secret.NewScanner(c)
	a.configPath = configPath
	return nil
}

func cleanPath(p string) string {
	if p == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(p))
}

func (a *SecretAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// Do not scan binaries
	binary, err := utils.IsBinary(input.Content, input.Info.Size())
	if err != nil || (binary && !allowedBinary(input.FilePath)) {
		return nil, nil
	}

	if size := input.Info.Size(); size > 10485760 { // 10MB
		log.WithPrefix("secret").Warn("The size of the scanned file is too large. It is recommended to use `--skip-files` for this file to avoid high memory consumption.", log.FilePath(input.FilePath), log.Int64("size (MB)", size/1048576))
	}

	filePath := input.FilePath
	// Files extracted from the image have an empty input.Dir.
	// Also, paths to these files do not have "/" prefix.
	// We need to add a "/" prefix to properly filter paths from the config file.
	if input.Dir == "" { // add leading `/` for files extracted from image
		filePath = fmt.Sprintf("/%s", filePath)
	}

	reader := input.Content
	if binary {
		content, err := utils.ExtractPrintableBytes(input.Content)
		if err != nil {
			return nil, xerrors.Errorf("binary read error %s: %w", input.FilePath, err)
		}
		reader = bytes.NewReader(content)
	}

	result := a.scanner.Scan(secret.ScanArgs{
		FilePath: filePath,
		Content:  reader,
		Binary:   binary,
	})

	if len(result.Findings) == 0 {
		return nil, nil
	}

	return &analyzer.AnalysisResult{
		Secrets: []types.Secret{result},
	}, nil
}

func (a *SecretAnalyzer) Required(filePath string, fi os.FileInfo) bool {
	if fi.Size() < 10 {
		return false
	}

	// Skip the secret-scanner config file itself.
	// a.configPath is already cleaned/slash-normalized in Init; filePath is scan-relative
	// from the walker but may carry native separators on Windows, so normalize it too.
	// We accept filePath as a path-boundary suffix of configPath to handle the common case
	// where --secret-config is given relative to CWD (so it carries a scan-root prefix that
	// the walker strips from filePath). This trades off a rare over-skip (same-basename
	// file elsewhere in the scan tree) for correctness in the common case.
	if a.configPath != "" {
		cleanFile := cleanPath(filePath)
		if a.configPath == cleanFile || strings.HasSuffix(a.configPath, "/"+cleanFile) {
			return false
		}
	}

	if a.scanner.IsSkipped(filePath) {
		return false
	}

	if a.scanner.AllowPath(filePath) {
		return false
	}

	return true
}

func (a *SecretAnalyzer) Type() analyzer.Type {
	return analyzer.TypeSecret
}

func (a *SecretAnalyzer) Version() int {
	return version
}
