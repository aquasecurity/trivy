package compare

import (
	"regexp"
	"strings"
)

// NormalizeConstraintString splits a constraint string that has multiple OR ranges
// separated by spaces into properly formatted ranges joined with " || ".
//
// Expected format from trivy-db: ">=X, <Y >=Z, <W ..."
// - Comma (,) = AND within a range
// - Space (between complete ranges) = OR between ranges
//
// The constraint parsing libraries (go-npm-version, go-pep440-version, go-gem-version,
// bitnami/go-version) expect OR groups to be separated by "||", not spaces.
// Example: ">=1.0.0, <2.0.0 >=2.0.0, <3.0.0" -> ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0"
//
// This function normalizes space-separated OR groups to ||-separated groups
// to ensure proper parsing by these libraries.
func NormalizeConstraintString(constraint string) string {
	// If the constraint already contains "||", assume it's already normalized
	if strings.Contains(constraint, "||") {
		return constraint
	}

	// Pattern to match constraint operators at the start of a token
	operatorPattern := regexp.MustCompile(`^\s*(>=|<=|>|<|==|!=|=|~|\^)`)
	var ranges []string
	var currentRange strings.Builder
	parts := strings.Fields(constraint)

	for i, part := range parts {
		if currentRange.Len() > 0 {
			currentRange.WriteString(" ")
		}
		currentRange.WriteString(part)

		// If this part doesn't end with a comma (not part of an AND group)
		// and the next part starts with an operator, we've reached the end of a range
		if !strings.HasSuffix(part, ",") && i < len(parts)-1 {
			nextIsNewConstraint := operatorPattern.MatchString(parts[i+1])
			if nextIsNewConstraint {
				ranges = append(ranges, strings.TrimSpace(currentRange.String()))
				currentRange.Reset()
			}
		}
	}

	// Add the last range if any
	if currentRange.Len() > 0 {
		ranges = append(ranges, strings.TrimSpace(currentRange.String()))
	}

	// If we only have one range, return the original constraint
	if len(ranges) <= 1 {
		return constraint
	}

	// Join ranges with " || "
	return strings.Join(ranges, " || ")
}

