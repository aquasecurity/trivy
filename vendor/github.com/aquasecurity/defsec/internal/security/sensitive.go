package security

import (
	"strings"
)

var sensitiveAttributeTokens = []string{
	"password",
	"secret",
	"private_key",
	"aws_access_key_id",
	"aws_secret_access_key",
	"token",
	"api_key",
}

var whitelistTokens = []string{
	"token_type",
	"version",
}

func IsSensitiveAttribute(name string) bool {
	name = strings.ToLower(name)

	for _, criterionToken := range sensitiveAttributeTokens {
		if name == criterionToken {
			return true
		}
		if strings.Contains(name, criterionToken) {
			for _, exclusionToken := range whitelistTokens {
				if strings.HasSuffix(name, exclusionToken) {
					return false
				}
			}
			return true
		}
	}

	return false
}
