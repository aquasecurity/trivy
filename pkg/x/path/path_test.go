package path

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContains(t *testing.T) {
	type args struct {
		filePath string
		subpath  string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "file",
			args: args{
				filePath: "go.mod",
				subpath:  "go.mod",
			},
			want: true,
		},
		{
			name: "dir",
			args: args{
				filePath: "app/node_modules/express/package.json",
				subpath:  "node_modules",
			},
			want: true,
		},
		{
			name: "path",
			args: args{
				filePath: "app/node_modules/express/package.json",
				subpath:  "app/node_modules",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Contains(tt.args.filePath, tt.args.subpath)
			assert.Equal(t, tt.want, got)
		})
	}
}
