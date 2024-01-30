package functions

import (
	"crypto/sha256"
	"strings"

	"github.com/google/uuid"
)

func Guid(args ...interface{}) interface{} {

	if len(args) == 0 {
		return ""
	}

	hashParts := make([]string, len(args))
	for i, str := range args {
		hashParts[i] = str.(string)
	}

	guid, err := generateSeededGUID(hashParts...)
	if err != nil {
		return ""
	}

	return guid.String()
}

func generateSeededGUID(seedParts ...string) (uuid.UUID, error) {
	var id uuid.UUID

	stringToHash := strings.Join(seedParts, "")

	hsha2 := sha256.Sum256([]byte(stringToHash))

	copy(id[:], hsha2[:16])
	id[6] = (id[6] & 0x0f) | 0x40 // Version 4
	id[8] = (id[8] & 0x3f) | 0x80 // Variant is 10
	return id, nil
}

func NewGuid(args ...interface{}) interface{} {
	return uuid.NewString()
}
