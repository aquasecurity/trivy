package uuid

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

var newUUID func() uuid.UUID = uuid.New

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

func New() uuid.UUID {
	return newUUID()
}
