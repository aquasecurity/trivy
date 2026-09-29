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
	Layer     Layer `json:",omitzero"`
	Offset    int   `json:",omitempty"` // Byte offset in the original file
}
