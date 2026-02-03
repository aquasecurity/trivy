package severity

import (
	"slices"
	"strings"
)

type Severity string

const (
	None     Severity = ""
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
)

var ValidSeverity = []Severity{
	Critical, High, Medium, Low,
}

func (s *Severity) IsValid() bool {
	return slices.Contains(ValidSeverity, *s)
}

func (s *Severity) Valid() []Severity {
	return ValidSeverity
}

func StringToSeverity(sev string) Severity {
	s := strings.ToUpper(sev)
	switch s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return Severity(s)
	case "ERROR":
		return High
	case "WARNING":
		return Medium
	case "INFO":
		return Low
	default:
		return None
	}
}
