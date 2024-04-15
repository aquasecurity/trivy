package dependency_test

import (
	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestID(t *testing.T) {
	type args struct {
		ltype   types.LangType
		name    string
		version string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "conan",
			args: args{
				ltype:   types.Conan,
				name:    "test",
				version: "1.0.0",
			},
			want: "test/1.0.0",
		},
		{
			name: "go module",
			args: args{
				ltype:   types.GoModule,
				name:    "test",
				version: "1.0.0",
			},
			want: "test@v1.0.0",
		},
		{
			name: "gradle",
			args: args{
				ltype:   types.Gradle,
				name:    "test",
				version: "1.0.0",
			},
			want: "test:1.0.0",
		},
		{
			name: "pip",
			args: args{
				ltype:   types.Pip,
				name:    "test",
				version: "1.0.0",
			},
			want: "test@1.0.0",
		},
		{
			name: "no version",
			args: args{
				ltype:   types.Pom,
				name:    "test",
				version: "",
			},
			want: "test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dependency.ID(tt.args.ltype, tt.args.name, tt.args.version)
			assert.Equal(t, tt.want, got)
		})
	}
}
