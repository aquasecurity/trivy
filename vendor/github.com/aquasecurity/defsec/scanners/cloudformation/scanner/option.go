package scanner

import "io"

// Option - scanner options for passing arguments into the scanner
type Option func(s *Scanner)

// OptionWithDebug - pass the scanner an io.Writer to log debug messages to
func OptionWithDebug(debugWriter io.Writer) func(s *Scanner) {
	return func(s *Scanner) {
		s.debugWriter = debugWriter
	}
}

// OptionIncludePassed - tell the scanner to include results for passes checks
func OptionIncludePassed() func(s *Scanner) {
	return func(s *Scanner) {
		s.includePassed = true
	}
}

// OptionIncludeIgnored - tell the scanner to include results that would otherwise be ignored
func OptionIncludeIgnored() func(s *Scanner) {
	return func(s *Scanner) {
		s.includeIgnored = true
	}
}

// OptionWithExcludedIDs - tell the scanner to exclude the provided IDs
func OptionWithExcludedIDs(exludedIDs []string) func(s *Scanner) {
	return func(s *Scanner) {
		s.excludedRuleIDs = exludedIDs
	}
}

// OptionWithPolicyDirs - location of rego policy directories - policies are loaded recursively
func OptionWithPolicyDirs(dirs []string) func(s *Scanner) {
	return func(s *Scanner) {
		s.policyDirs = dirs
	}
}

// OptionWithPolicyNamespaces - namespaces which indicate rego policies containing enforced rules
func OptionWithPolicyNamespaces(namespaces ...string) func(s *Scanner) {
	return func(s *Scanner) {
		s.policyNamespaces = namespaces
	}
}
