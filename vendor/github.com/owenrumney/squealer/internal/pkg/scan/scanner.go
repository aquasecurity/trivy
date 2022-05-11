package scan

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/owenrumney/squealer/internal/pkg/match"
	"github.com/owenrumney/squealer/internal/pkg/metrics"
	"github.com/owenrumney/squealer/pkg/config"
)

type ScannerType string

const (
	GitScanner       ScannerType = "gitScanner"
	DirectoryScanner ScannerType = "dirScanner"
	StringScanner    ScannerType = "stringScanner"
)

type ScannerConfig struct {
	Cfg            *config.Config
	Basepath       string
	Redacted       bool
	NoGit          bool
	FromHash       string
	ToHash         string
	Everything     bool
	CommitListFile string
}

type Scanner interface {
	Scan() ([]match.Transgression, error)
	GetMetrics() *metrics.Metrics
	GetType() ScannerType
}

func NewScanner(sc ScannerConfig) (Scanner, error) {
	if sc.NoGit || notGit(sc.Basepath) {
		log.Infof("Using a directory scanner to process %s\n", sc.Basepath)
		return newDirectoryScanner(sc)
	}
	log.Infof("Using a git scanner to process %s\n", sc.Basepath)
	return newGitScanner(sc)
}

func notGit(basepath string) bool {
	log.Debugf("checking if there is a git repository")
	if strings.HasPrefix(basepath, "git:") || strings.HasPrefix(basepath, "https://") {
		return false
	}
	if stat, err := os.Stat(basepath); err == nil && stat != nil {
		gitPath := fmt.Sprintf("%s/.git", basepath)
		if _, ok := os.Stat(gitPath); ok != nil {
			log.Debugf("could not find the git path: %s", gitPath)
			return true
		}
	}
	return false
}

func shouldIgnore(filename string, ignorePaths []string, ignoreExtensions []string) bool {
	for _, ignorePath := range ignorePaths {
		if match, err := regexp.MatchString(fmt.Sprintf(`\b%s\b`, ignorePath), filename); err == nil && match {
			return true
		}
	}
	for _, ext := range ignoreExtensions {
		if strings.HasSuffix(filename, ext) {
			return true
		}
	}
	return false
}
