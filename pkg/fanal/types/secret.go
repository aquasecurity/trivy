package types

type SecretRuleCategory string

type Secret struct {
	FilePath string
	Findings []SecretFinding
}

type SecretFinding struct {
	RuleID    string
	Category  SecretRuleCategory
	Severity  string
	Title     string
	StartLine int
	EndLine   int
	Code      Code
	Match     string
	Deleted   bool
	Layer     Layer `json:",omitempty"`
}
