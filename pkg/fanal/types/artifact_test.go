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

func TestOS_Merge(t *testing.T) {
	tests := []struct {
		name  string
		os    OS
		newOS OS
		want  OS
	}{
		{
			name:  "empty new OS is ignored",
			os:    OS{Family: Alpine, Name: "3.20.3"},
			newOS: OS{},
			want:  OS{Family: Alpine, Name: "3.20.3"},
		},
		{
			name:  "fill in missing fields",
			os:    OS{Family: Alpine},
			newOS: OS{Family: Alpine, Name: "3.20.3"},
			want:  OS{Family: Alpine, Name: "3.20.3"},
		},
		{
			name:  "existing fields win",
			os:    OS{Family: Alpine, Name: "3.20.3"},
			newOS: OS{Family: Alpine, Name: "3.21.0"},
			want:  OS{Family: Alpine, Name: "3.20.3"},
		},
		{
			name:  "extended is sticky",
			os:    OS{Family: Ubuntu, Name: "18.04", Extended: true},
			newOS: OS{Family: Ubuntu, Name: "18.04"},
			want:  OS{Family: Ubuntu, Name: "18.04", Extended: true},
		},
		{
			name:  "supplier is carried over",
			os:    OS{Family: Alpine, Name: "3.20.3"},
			newOS: OS{Family: Alpine, Name: "3.20.3", Supplier: SupplierSeal},
			want:  OS{Family: Alpine, Name: "3.20.3", Supplier: SupplierSeal},
		},
		{
			name:  "existing supplier wins over a different one",
			os:    OS{Family: Alpine, Name: "3.20.3", Supplier: SupplierSeal},
			newOS: OS{Family: Alpine, Name: "3.20.3", Supplier: Supplier("other")},
			want:  OS{Family: Alpine, Name: "3.20.3", Supplier: SupplierSeal},
		},
		{
			name:  "empty OS takes everything from the new one",
			os:    OS{},
			newOS: OS{Family: Alpine, Name: "3.20.3", Supplier: SupplierSeal},
			want:  OS{Family: Alpine, Name: "3.20.3", Supplier: SupplierSeal},
		},
		{
			// RedHat and Debian are overwritten wholesale, see OS.Merge.
			name:  "redhat is replaced by the new OS",
			os:    OS{Family: RedHat, Name: "8.9", Supplier: SupplierSeal},
			newOS: OS{Family: Oracle, Name: "8.9"},
			want:  OS{Family: Oracle, Name: "8.9"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.os.Merge(tt.newOS)
			assert.Equal(t, tt.want, tt.os)
		})
	}
}
