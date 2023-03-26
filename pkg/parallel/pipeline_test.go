package parallel_test

import (
	"context"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/parallel"
)

func TestPipeline_Do(t *testing.T) {
	type field struct {
		numWorkers int
		items      []float64
		onItem     func(float64) (float64, error)
	}
	type testCase struct {
		name    string
		field   field
		want    float64
		wantErr bool
	}
	tests := []testCase{
		{
			name: "pow",
			field: field{
				numWorkers: 5,
				items: []float64{
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
				onItem: func(f float64) (float64, error) {
					return math.Pow(f, 2), nil
				},
			},
			want: 385,
		},
		{
			name: "ceil",
			field: field{
				numWorkers: 3,
				items: []float64{
					1.1,
					2.2,
					3.3,
					4.4,
					5.5,
					-1.1,
					-2.2,
					-3.3,
				},
				onItem: func(f float64) (float64, error) {
					return math.Round(f), nil
				},
			},
			want: 10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got float64
			p := parallel.NewPipeline(tt.field.numWorkers, false, tt.field.items, tt.field.onItem, func(f float64) error {
				got += f
				return nil
			})
			err := p.Do(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
