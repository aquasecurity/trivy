package functions

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func UniqueString(args ...any) any {
	if len(args) == 0 {
		return ""
	}

	hashParts := make([]string, len(args))
	for i, str := range args {
		hashParts[i] = str.(string)
	}

	hash := sha256.New().Sum([]byte(strings.Join(hashParts, "")))
	return hex.EncodeToString(hash)[:13]
}
