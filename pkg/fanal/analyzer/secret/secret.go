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
		configPath: configPath,
	}
}

// Init initializes and sets a secret scanner
func (a *SecretAnalyzer) Init(opt analyzer.AnalyzerOptions) error {
	if opt.SecretScannerOption.ConfigPath == a.configPath && !lo.IsEmpty(a.scanner) {
		// This check is for tools importing Trivy and customize analyzers
		// Never reach here in Trivy OSS
		return nil
	}
	configPath := opt.SecretScannerOption.ConfigPath
	c, err := secret.ParseConfig(configPath)
	if err != nil {
		return xerrors.Errorf("secret config error: %w", err)
	}
	a.scanner = secret.NewScanner(c)
	a.configPath = configPath
	return nil
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
	// filePath is scan-relative and slash-normalized by the walker; configPath comes from the
	// --secret-config flag verbatim and may carry a scan-root prefix or native separators, so
	// normalize both and accept filePath as a path-boundary suffix of configPath. This trades
	// off a rare over-skip (same-basename file elsewhere in the scan tree) for correctly
	// handling the common case where the flag value is given relative to CWD, not scan root.
	if a.configPath != "" {
		cleanFile := filepath.ToSlash(filepath.Clean(filePath))
		cleanConfig := filepath.ToSlash(filepath.Clean(a.configPath))
		if cleanConfig == cleanFile || strings.HasSuffix(cleanConfig, "/"+cleanFile) {
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
