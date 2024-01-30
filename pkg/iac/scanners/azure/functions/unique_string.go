package functions

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

func UniqueString(args ...interface{}) interface{} {
	if len(args) == 0 {
		return ""
	}

	hashParts := make([]string, len(args))
	for i, str := range args {
		hashParts[i] = str.(string)
	}

	hash := sha256.New().Sum([]byte(strings.Join(hashParts, "")))
	return fmt.Sprintf("%x", hash)[:13]
}
