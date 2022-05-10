package squealer

import "github.com/owenrumney/squealer/pkg/config"

type Option func(s *Scanner)

func OptionWithConfig(config config.Config) Option {
	return func(s *Scanner) {
		s.config = &config
	}
}

func OptionRedactedSecrets(redacted bool) Option {
	return func(s *Scanner) {
		s.redacted = redacted
	}
}

func OptionNoGitScan(noGit bool) Option {
	return func(s *Scanner) {
		s.noGit = noGit
	}
}

func OptionWithScanEverything(everything bool) Option {
	return func(s *Scanner) {
		s.everything = everything
	}
}

func OptionWithBasePath(basePath string) Option {
	return func(s *Scanner) {
		s.basePath = basePath
	}
}

func OptionWithFromHash(fromHash string) Option {
	return func(s *Scanner) {
		s.fromHash = fromHash
	}
}

func OptionWithToHash(toHash string) Option {
	return func(s *Scanner) {
		s.toHash = toHash
	}
}

func OptionWithCommitListFile(commitListFile string) Option {
	return func(s *Scanner) {
		s.commitListFile = commitListFile
	}
}
