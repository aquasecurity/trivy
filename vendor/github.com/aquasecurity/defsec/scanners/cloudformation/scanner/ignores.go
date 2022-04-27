package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/rules"
)

func isIgnored(scanResult rules.Result) bool {
	ref := scanResult.Metadata().Reference()

	if cfRef, ok := ref.(*parser.CFReference); ok {
		if ignore, err := parseIgnore(cfRef.Comment()); err == nil {
			if ignore.RuleID != scanResult.Rule().AVDID && ignore.RuleID != scanResult.Rule().LongID() {
				return false
			}
			if ignore.Expiry == nil || time.Now().Before(*ignore.Expiry) {
				return true
			}
		}

	}
	return false
}

type Ignore struct {
	RuleID string
	Expiry *time.Time
}

func parseIgnore(comment string) (*Ignore, error) {

	comment = strings.TrimSpace(comment)
	comment = strings.TrimPrefix(comment, "#")
	comment = strings.TrimPrefix(comment, "//")
	comment = strings.TrimSpace(comment)

	var ignore Ignore
	if !strings.HasPrefix(comment, "cfsec:") {
		return nil, fmt.Errorf("invalid ignore")
	}

	comment = comment[6:]

	segments := strings.Split(comment, ":")

	for i := 0; i < len(segments)-1; i += 2 {
		key := segments[i]
		val := segments[i+1]
		switch key {
		case "ignore":
			ignore.RuleID = val
		case "exp":
			parsed, err := time.Parse("2006-01-02", val)
			if err != nil {
				return nil, err
			}
			ignore.Expiry = &parsed
		}
	}

	return &ignore, nil
}
