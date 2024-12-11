package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOS_String(t *testing.T) {
	type fields struct {
		Family OSType
		Name   string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "family and name",
			fields: fields{
				Family: OSType("ubuntu"),
				Name:   "22.04",
			},
			want: "ubuntu/22.04",
		},
		{
			name: "empty name",
			fields: fields{
				Family: OSType("ubuntu"),
				Name:   "",
			},
			want: "ubuntu",
		},
		{
			name: "empty",
			fields: fields{
				Family: "",
				Name:   "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OS{
				Family: tt.fields.Family,
				Name:   tt.fields.Name,
			}
			assert.Equal(t, tt.want, o.String())
		})
	}
}
