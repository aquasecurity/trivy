package squealer

import (
	"github.com/owenrumney/squealer/internal/pkg/match"
	"github.com/owenrumney/squealer/internal/pkg/metrics"
	"github.com/owenrumney/squealer/internal/pkg/scan"
	"github.com/owenrumney/squealer/pkg/config"
)

type Scanner struct {
	redacted       bool
	config         *config.Config
	scanner        scan.Scanner
	basePath       string
	noGit          bool
	fromHash       string
	toHash         string
	everything     bool
	commitListFile string
}

func New(options ...Option) (*Scanner, error) {
	scanner := &Scanner{
		config:     config.DefaultConfig(),
		redacted:   false,
		basePath:   ".",
		noGit:      false,
		fromHash:   "",
		toHash:     "",
		everything: false,
	}

	for _, opt := range options {
		opt(scanner)
	}

	s, err := scan.NewScanner(scan.ScannerConfig{
		Cfg:            scanner.config,
		Basepath:       scanner.basePath,
		Redacted:       scanner.redacted,
		NoGit:          scanner.noGit,
		Everything:     scanner.everything,
		FromHash:       scanner.fromHash,
		ToHash:         scanner.toHash,
		CommitListFile: scanner.commitListFile,
	})

	if err != nil {
		return nil, err
	}
	scanner.scanner = s
	return scanner, nil
}

func (s Scanner) Scan() ([]match.Transgression, error) {
	return s.scanner.Scan()
}

func (s Scanner) GetMetrics() *metrics.Metrics {
	return s.scanner.GetMetrics()
}
