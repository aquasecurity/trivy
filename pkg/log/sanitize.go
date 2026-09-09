package log

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/set"
)

const maskedSecret = "********"

var sensitiveKeys = set.New(
	"password", "passwd", "secret", "token",
	"access_token", "api_key", "client_secret", "private_key",
	"authorization", "credential", "credentials",
)

// isSensitiveKey checks whether a log attribute key represents sensitive data
func isSensitiveKey(key string) bool {
	return sensitiveKeys.Contains(strings.ToLower(key))
}

func hasSensitiveGroup(groups []string) bool {
	for _, g := range groups {
		if isSensitiveKey(g) {
			return true
		}
	}
	return false
}
