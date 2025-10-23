package uuid

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

type UUID = uuid.UUID

var (
	Nil       = uuid.Nil
	MustParse = uuid.MustParse
)

// uuidKey is the context key for UUID generator. It is unexported to prevent collisions with context keys defined in
// other packages.
type uuidKey struct{}

// generator is an unexported interface for UUID generation.
type generator interface {
	new() UUID
}

// realGenerator generates real UUIDs using the standard library.
type realGenerator struct{}

func (realGenerator) new() UUID {
	return uuid.New()
}

// fakeGenerator generates predictable UUIDs for testing.
type fakeGenerator struct {
	format string
	mu     sync.Mutex
	count  int
}

func (g *fakeGenerator) new() UUID {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.count++
	return uuid.Must(uuid.Parse(fmt.Sprintf(g.format, g.count)))
}

// With returns a new context with a fake UUID generator for testing.
// The 'format' is used to generate a fake UUID and must contain a single '%d' which will be replaced with a counter.
func With(ctx context.Context, format string) context.Context {
	gen := &fakeGenerator{
		format: format,
	}
	return context.WithValue(ctx, uuidKey{}, gen)
}

// New generates a new UUID using the generator from context.
// If no generator is found in the context, a real UUID is generated.
func New(ctx context.Context) UUID {
	return generatorFromContext(ctx).new()
}

// generatorFromContext returns the UUID generator from context.
// If no generator is found, returns a real generator.
func generatorFromContext(ctx context.Context) generator {
	g, ok := ctx.Value(uuidKey{}).(generator)
	if !ok {
		return realGenerator{}
	}
	return g
}
