package log

import (
	"regexp"
	"strings"
)

const maskedSecret = "********"

var (
	// urlCredentialsRegex matches user:password in URLs like http(s)://, git://, ssh://, ftp://, redis://
	urlCredentialsRegex = regexp.MustCompile(`((?:https?|ftp|git|ssh|redis)://[^:\s/@]+):([^@\s/]+)@`)

	// urlQueryParamsRegex matches sensitive query parameters in URLs
	urlQueryParamsRegex = regexp.MustCompile(`(?i)([?&](?:token|access_token|api_token|api_key|apikey|secret|client_secret|password|passwd|pwd|auth|signature)=)[^&\s]+`)

	// kvPattern matches key=value or key: value pairs where key is a sensitive word
	kvPattern = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api_token|apitoken|access_token|client_secret|auth_token|private_key|api_key|apikey|access_key|accesskey|secret_key|secretkey|shared_secret)\b\s*([:=])\s*(?:["']([^"']*)["']|([^\s"',;]+))`)

	// jsonPattern matches JSON fields like "password": "value"
	jsonPattern = regexp.MustCompile(`(?i)"(password|passwd|pwd|secret|token|api_token|apitoken|access_token|client_secret|auth_token|private_key|api_key|apikey|access_key|accesskey|secret_key|secretkey|shared_secret)"\s*:\s*"([^"]*)"`)

	// authHeaderPattern matches Bearer and Basic tokens
	bearerPattern    = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*`)
	basicAuthPattern = regexp.MustCompile(`(?i)\bBasic\s+[A-Za-z0-9+/]{8,}={0,2}`)

	// privateKeyPattern matches PEM private key blocks
	privateKeyPattern = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----`)

	// sensitiveKeyWords are checked against attribute keys
	sensitiveKeyWords = []string{
		"password",
		"passwd",
		"pwd",
		"secret",
		"token",
		"credential",
		"private_key",
		"private-key",
		"privatekey",
		"api_key",
		"api-key",
		"apikey",
		"access_key",
		"access-key",
		"accesskey",
		"secret_key",
		"secret-key",
		"secretkey",
		"auth_key",
		"auth-key",
		"authorization",
		"cookie",
		"session",
		"signature",
	}
)

// isSensitiveKey checks whether a log attribute key represents sensitive data
func isSensitiveKey(key string) bool {
	if key == "" {
		return false
	}
	lower := strings.ToLower(key)

	// Check for dotted keys or path-like keys (e.g. registry.password, server.token)
	parts := strings.FieldsFunc(lower, func(r rune) bool {
		return r == '.' || r == '_' || r == '-' || r == '/'
	})

	for _, part := range parts {
		switch part {
		case "password", "passwd", "pwd", "secret", "token", "credential", "credentials", "auth", "authorization", "cookie", "session", "signature":
			return true
		}
	}

	for _, kw := range sensitiveKeyWords {
		if strings.Contains(lower, kw) {
			return true
		}
	}

	return false
}

func hasSensitiveGroup(groups []string) bool {
	for _, g := range groups {
		if isSensitiveKey(g) {
			return true
		}
	}
	return false
}

// sanitizeText masks credentials, tokens, and passwords in arbitrary text (log messages, error strings, etc.)
func sanitizeText(text string) string {
	if text == "" {
		return text
	}

	// 1. Private keys
	if strings.Contains(text, "PRIVATE KEY") {
		text = privateKeyPattern.ReplaceAllString(text, "[PRIVATE KEY REDACTED]")
	}

	// 2. URL embedded user:pass credentials
	if strings.Contains(text, "://") && strings.Contains(text, "@") {
		text = urlCredentialsRegex.ReplaceAllString(text, "${1}:"+maskedSecret+"@")
	}

	// 3. URL query parameters
	if strings.Contains(text, "?") || strings.Contains(text, "&") {
		text = urlQueryParamsRegex.ReplaceAllString(text, "${1}"+maskedSecret)
	}

	// 4. JSON patterns: "password": "value"
	if strings.Contains(text, `"`) && strings.Contains(text, `:`) {
		text = jsonPattern.ReplaceAllString(text, `"${1}": "`+maskedSecret+`"`)
	}

	// 5. Key-Value patterns: password=value or password: value
	text = kvPattern.ReplaceAllStringFunc(text, func(match string) string {
		// Find the delimiter (: or =)
		sepIdx := strings.IndexAny(match, ":=")
		if sepIdx == -1 {
			return match
		}
		keyPart := match[:sepIdx]
		delim := match[sepIdx : sepIdx+1]
		rest := match[sepIdx+1:]
		// preserve leading whitespace after delimiter
		leadingSpaces := ""
		for _, r := range rest {
			if r == ' ' || r == '\t' {
				leadingSpaces += string(r)
			} else {
				break
			}
		}
		return keyPart + delim + leadingSpaces + maskedSecret
	})

	// 6. Bearer tokens
	if strings.Contains(strings.ToLower(text), "bearer ") {
		text = bearerPattern.ReplaceAllString(text, "Bearer "+maskedSecret)
	}

	// 7. Basic auth header
	if strings.Contains(strings.ToLower(text), "basic ") {
		text = basicAuthPattern.ReplaceAllString(text, "Basic "+maskedSecret)
	}

	return text
}
