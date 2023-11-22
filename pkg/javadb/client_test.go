package javadb

import (
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFoundGroupID(t *testing.T) {
	tests := []struct {
		name        string
		indexes     []types.Index
		version     string
		wantGroupID string
	}{
		{
			name: "Only one groupID has required version",
			indexes: []types.Index{
				{
					GroupID: "com.example1",
					Version: "1.0.0",
				},
				{
					GroupID: "com.example1",
					Version: "1.0.1",
				},
				{
					GroupID: "com.example2",
					Version: "2.0.0",
				},
			},
			version:     "2.0.0",
			wantGroupID: "com.example2",
		},
		{
			name: "Two groupIDs have required version",
			indexes: []types.Index{
				{
					GroupID: "com.example1",
					Version: "1.0.0",
				},
				{
					GroupID: "com.example2",
					Version: "1.0.1",
				},
				{
					GroupID: "com.example2",
					Version: "1.0.0",
				},
			},
			version:     "1.0.0",
			wantGroupID: "com.example2",
		},
		{
			name: "There are no groupIDs with required version",
			indexes: []types.Index{
				{
					GroupID: "com.example1",
					Version: "1.0.0",
				},
				{
					GroupID: "com.example1",
					Version: "2.0.0",
				},
				{
					GroupID: "com.example2",
					Version: "2.0.0",
				},
			},
			version:     "3.0.0",
			wantGroupID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotGroupID := foundGroupID(tt.version, tt.indexes)
			assert.Equal(t, tt.wantGroupID, gotGroupID)
		})
	}
}
