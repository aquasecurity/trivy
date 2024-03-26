//go:build !tinygo.wasm

package uuid

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

type UUID = uuid.UUID

var (
	newUUID   func() uuid.UUID = uuid.New
	Nil                        = uuid.Nil
	MustParse                  = uuid.MustParse
)

// SetFakeUUID sets a fake UUID for testing.
// The 'format' is used to generate a fake UUID and
// must contain a single '%d' which will be replaced with a counter.
func SetFakeUUID(t *testing.T, format string) {
	var count int
	newUUID = func() uuid.UUID {
		count++
		return uuid.Must(uuid.Parse(fmt.Sprintf(format, count)))
	}
	t.Cleanup(func() {
		newUUID = uuid.New
	})
}

func New() UUID {
	return newUUID()
}
