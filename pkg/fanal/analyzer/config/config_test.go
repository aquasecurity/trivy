package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
)

func TestScannerOption_Sort(t *testing.T) {
	type fields struct {
		Namespaces  []string
		PolicyPaths []string
		DataPaths   []string
	}
	tests := []struct {
		name   string
		fields fields
		want   config.ScannerOption
	}{
		{
			name: "happy path",
			fields: fields{
				Namespaces:  []string{"main", "custom", "default"},
				PolicyPaths: []string{"policy"},
				DataPaths:   []string{"data/b", "data/c", "data/a"},
			},
			want: config.ScannerOption{
				Namespaces:  []string{"custom", "default", "main"},
				PolicyPaths: []string{"policy"},
				DataPaths:   []string{"data/a", "data/b", "data/c"},
			},
		},
		{
			name: "missing some fields",
			fields: fields{
				Namespaces:  []string{"main"},
				PolicyPaths: nil,
				DataPaths:   nil,
			},
			want: config.ScannerOption{
				Namespaces: []string{"main"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := config.ScannerOption{
				Namespaces:  tt.fields.Namespaces,
				PolicyPaths: tt.fields.PolicyPaths,
				DataPaths:   tt.fields.DataPaths,
			}
			o.Sort()

			assert.Equal(t, tt.want, o)
		})
	}
}
