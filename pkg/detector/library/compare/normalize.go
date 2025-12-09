package compare

import (
	"regexp"
	"strings"
)

// ComparerType identifies the type of comparer for constraint normalization
type ComparerType int

const (
	ComparerTypeNPM ComparerType = iota
	ComparerTypePEP440
	ComparerTypeRubyGems
	ComparerTypeBitnami
	ComparerTypeMaven
)

// NormalizeConstraintString converts space-separated OR ranges to ||-separated format.
//
// Constraints format:
//   - Comma (,) = AND within a range
//   - Space between ranges = OR between ranges
//   - Maven supports both comma and space for AND
//
// Example: ">=1.0.0, <2.0.0 >=2.0.0, <3.0.0" -> ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0"
func NormalizeConstraintString(constraint string, comparerType ComparerType) string {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" || strings.Contains(constraint, "||") {
		return constraint
	}

	operatorPattern := regexp.MustCompile(`^\s*(>=|<=|>|<|==|!=|=|~|\^|\(|\[)`)
	greaterOpPattern := regexp.MustCompile(`^\s*(>=|>|\(|\[)`)
	var ranges []string
	var currentRange strings.Builder
	parts := strings.Fields(constraint)

	for i, part := range parts {
		if currentRange.Len() > 0 {
			currentRange.WriteString(" ")
		}
		currentRange.WriteString(part)

		var shouldSplit bool

		if comparerType == ComparerTypeMaven {
			if i < len(parts)-1 {
				nextIsGreaterOp := greaterOpPattern.MatchString(parts[i+1])
				if nextIsGreaterOp {
					isLessOp := strings.HasPrefix(part, "<") || strings.HasPrefix(part, "<=")
					endsWithBracket := strings.HasSuffix(part, ")") || strings.HasSuffix(part, "]")
					isVersion := !operatorPattern.MatchString(part)
					prevIsLessOp := i > 0 && (strings.HasPrefix(parts[i-1], "<") || strings.HasPrefix(parts[i-1], "<="))
					prevPrevEndsWithComma := i > 1 && strings.HasSuffix(parts[i-2], ",")
					shouldSplit = isLessOp || endsWithBracket || (isVersion && prevIsLessOp && prevPrevEndsWithComma)
				}
			}
		} else {
			if !strings.HasSuffix(part, ",") && i < len(parts)-1 {
				shouldSplit = greaterOpPattern.MatchString(parts[i+1])
			}
		}

		if shouldSplit {
			ranges = append(ranges, strings.TrimSpace(currentRange.String()))
			currentRange.Reset()
		}
	}

	if currentRange.Len() > 0 {
		ranges = append(ranges, strings.TrimSpace(currentRange.String()))
	}

	if len(ranges) <= 1 {
		return constraint
	}

	return strings.Join(ranges, " || ")
}

