package types

type SecretRuleCategory string

type Secret struct {
	FilePath string
	Findings []SecretFinding
	Layer    Layer `json:",omitempty"`
}

type SecretFinding struct {
	RuleID    string
	Category  SecretRuleCategory
	Severity  string
	Title     string
	StartLine int
	EndLine   int
	Match     string
}
