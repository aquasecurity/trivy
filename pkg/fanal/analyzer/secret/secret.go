package secret

import (
	"bytes"
	"context"
	"fmt"
	"io"
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

var (
	skipFiles = []string{
		"go.mod",
		"go.sum",
		"package-lock.json",
		"yarn.lock",
		"pnpm-lock.yaml",
		"Pipfile.lock",
		"Gemfile.lock",
	}
	skipDirs = []string{
		".git",
		"node_modules",
	}
	skipExts = []string{
		".jpg",
		".png",
		".gif",
		".doc",
		".pdf",
		".bin",
		".svg",
		".socket",
		".deb",
		".rpm",
		".zip",
		".gz",
		".gzip",
		".tar",
	}

	allowedBinaries = []string{
		".pyc",
	}
)

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

	var content []byte

	if !binary {
		content, err = io.ReadAll(input.Content)
		if err != nil {
			return nil, xerrors.Errorf("read error %s: %w", input.FilePath, err)
		}
		content = bytes.ReplaceAll(content, []byte("\r"), []byte(""))
	} else {
		content, err = utils.ExtractPrintableBytes(input.Content)
		if err != nil {
			return nil, xerrors.Errorf("binary read error %s: %w", input.FilePath, err)
		}
	}

	filePath := input.FilePath
	// Files extracted from the image have an empty input.Dir.
	// Also, paths to these files do not have "/" prefix.
	// We need to add a "/" prefix to properly filter paths from the config file.
	if input.Dir == "" { // add leading `/` for files extracted from image
		filePath = fmt.Sprintf("/%s", filePath)
	}

	result := a.scanner.Scan(secret.ScanArgs{
		FilePath: filePath,
		Content:  content,
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
	// Skip small files
	if fi.Size() < 10 {
		return false
	}

	dir, fileName := filepath.Split(filePath)
	dir = filepath.ToSlash(dir)
	dirs := strings.Split(dir, "/")

	// Check if the directory should be skipped
	for _, skipDir := range skipDirs {
		if slices.Contains(dirs, skipDir) {
			return false
		}
	}

	// Check if the file should be skipped
	if slices.Contains(skipFiles, fileName) {
		return false
	}

	// Skip the config file for secret scanning
	if filepath.Base(a.configPath) == filePath {
		return false
	}

	// Check if the file extension should be skipped
	ext := filepath.Ext(fileName)
	if slices.Contains(skipExts, ext) {
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
