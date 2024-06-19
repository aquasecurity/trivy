package pom

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_evaluateVariable(t *testing.T) {
	type args struct {
		s     string
		props map[string]string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "happy path",
			args: args{
				s: "${java.version}",
				props: map[string]string{
					"java.version": "1.7",
				},
			},
			want: "1.7",
		},
		{
			name: "two variables",
			args: args{
				s: "${foo.name}-${bar.name}",
				props: map[string]string{
					"foo.name": "aaa",
					"bar.name": "bbb",
				},
			},
			want: "aaa-bbb",
		},
		{
			name: "looped variables",
			args: args{
				s: "${foo.name}",
				props: map[string]string{
					"foo.name": "${bar.name}",
					"bar.name": "${foo.name}",
				},
			},
			want: "",
		},
		{
			name: "same variables",
			args: args{
				s: "${foo.name}-${foo.name}",
				props: map[string]string{
					"foo.name": "aaa",
				},
			},
			want: "aaa-aaa",
		},
		{
			name: "nested variables",
			args: args{
				s: "${jackson.version.core}",
				props: map[string]string{
					"jackson.version":      "2.12.1",
					"jackson.version.core": "${jackson.version}",
				},
			},
			want: "2.12.1",
		},
		{
			name: "environmental variable",
			args: args{
				s: "${env.TEST_GO_DEP_PARSER}",
			},
			want: "1.2.3",
		},
		{
			name: "no variable",
			args: args{
				s: "1.12",
			},
			want: "1.12",
		},
	}

	envName := "TEST_GO_DEP_PARSER"
	t.Setenv(envName, "1.2.3")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateVariable(tt.args.s, tt.args.props, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
