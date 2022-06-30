package misconf

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_FindingFSTarget(t *testing.T) {

	tests := []struct {
		input      []string
		wantTarget string
		wantPaths  []string
		wantErr    bool
	}{
		{
			input:   nil,
			wantErr: true,
		},
		{
			input:      []string{"/"},
			wantTarget: "/",
			wantPaths:  []string{"."},
		},
		{
			input:      []string{"/home/user"},
			wantTarget: "/home/user",
			wantPaths:  []string{"."},
		},
		{
			input:      []string{"/home/user", "/home/user/something"},
			wantTarget: "/home/user",
			wantPaths:  []string{".", "something"},
		},
		{
			input:      []string{"/home/user", "/home/user/something/else"},
			wantTarget: "/home/user",
			wantPaths:  []string{".", "something/else"},
		},
		{
			input:      []string{"/home/user", "/home/user2/something/else"},
			wantTarget: "/home",
			wantPaths:  []string{"user", "user2/something/else"},
		},
		{
			input:      []string{"/foo", "/bar"},
			wantTarget: "/",
			wantPaths:  []string{"foo", "bar"},
		},
		{
			input:      []string{"/", "/bar"},
			wantTarget: "/",
			wantPaths:  []string{".", "bar"},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%#v", test.input), func(t *testing.T) {
			target, paths, err := findFSTarget(test.input)
			if test.wantErr {
				require.Error(t, err)
			} else {
				assert.Equal(t, test.wantTarget, target)
				assert.Equal(t, test.wantPaths, paths)
			}
		})
	}

}
