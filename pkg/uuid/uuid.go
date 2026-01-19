package uuid

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

type UUID = uuid.UUID

var (
	newUUID   func() uuid.UUID          = uuid.New
	newUUIDV7 func() (uuid.UUID, error) = uuid.NewV7
	Nil                                 = uuid.Nil
	MustParse                           = uuid.MustParse
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

// SetFakeUUIDV7 sets a fake UUID v7 for testing.
// The 'format' is used to generate a fake UUID and
// must contain a single '%d' which will be replaced with a counter.
func SetFakeUUIDV7(t *testing.T, format string) {
	var count int
	newUUIDV7 = func() (uuid.UUID, error) {
		count++
		return uuid.Must(uuid.Parse(fmt.Sprintf(format, count))), nil
	}
	t.Cleanup(func() {
		newUUIDV7 = uuid.NewV7
	})
}

func New() UUID {
	return newUUID()
}

// NewV7 generates a new UUID version 7.
// UUIDv7 is time-ordered, combining a timestamp with random bits.
// This makes it suitable for use cases where ordering and database performance are important.
func NewV7() (UUID, error) {
	return newUUIDV7()
}
