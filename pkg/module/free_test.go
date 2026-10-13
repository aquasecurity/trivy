package module

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type freeStub struct {
	params [][]uint64
}

func (s *freeStub) Call(_ context.Context, params ...uint64) ([]uint64, error) {
	s.params = append(s.params, params)
	return nil, nil
}

func TestFreeInput(t *testing.T) {
	ctx := context.Background()

	t.Run("passes pointer and size", func(t *testing.T) {
		stub := &freeStub{}
		freeInput(ctx, stub, 8, 3)
		require.Len(t, stub.params, 1)
		assert.Equal(t, []uint64{8, 3}, stub.params[0])
	})

	t.Run("skips nil function and null pointer", func(t *testing.T) {
		stub := &freeStub{}
		assert.NotPanics(t, func() {
			freeInput(ctx, nil, 8, 3)
			freeInput(ctx, stub, 0, 3)
		})
		assert.Empty(t, stub.params)
	})
}
