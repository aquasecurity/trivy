package parallel_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/parallel"
)

func TestPipeline_Do(t *testing.T) {
	type field struct {
		numWorkers int
		items      []int
		onItem     func(context.Context, int) (int, error)
	}
	type testCase struct {
		name    string
		field   field
		want    int
		wantErr require.ErrorAssertionFunc
	}
	tests := []testCase{
		{
			name: "pow",
			field: field{
				numWorkers: 5,
				items: []int{
					1,
					2,
					3,
					4,
					5,
					6,
					7,
					8,
					9,
					10,
				},
				onItem: func(_ context.Context, i int) (int, error) {
					return i * i, nil
				},
			},
			want:    385,
			wantErr: require.NoError,
		},
		{
			name: "double",
			field: field{
				numWorkers: 3,
				items: []int{
					1,
					2,
					3,
					4,
					5,
					-1,
					-2,
					-3,
				},
				onItem: func(_ context.Context, i int) (int, error) {
					return i * 2, nil
				},
			},
			want:    18,
			wantErr: require.NoError,
		},
		{
			name: "error in series",
			field: field{
				numWorkers: 1,
				items: []int{
					1,
					2,
					3,
				},
				onItem: func(_ context.Context, _ int) (int, error) {
					return 0, errors.New("error")
				},
			},
			wantErr: require.Error,
		},
		{
			name: "error in parallel",
			field: field{
				numWorkers: 3,
				items: []int{
					1,
					2,
				},
				onItem: func(_ context.Context, _ int) (int, error) {
					return 0, errors.New("error")
				},
			},
			wantErr: require.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got int
			p := parallel.NewPipeline(tt.field.numWorkers, false, tt.field.items, tt.field.onItem, func(f int) error {
				got += f
				return nil
			})
			err := p.Do(context.Background())
			tt.wantErr(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
