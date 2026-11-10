package pom

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_displayURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "plain URL is kept",
			url:  "https://repo.example.com/maven2/com/example/a/1.0/a-1.0.pom",
			want: "https://repo.example.com/maven2/com/example/a/1.0/a-1.0.pom",
		},
		{
			name: "username and password are removed",
			url:  "https://user:pass@repo.example.com/maven2/a-1.0.pom",
			want: "https://repo.example.com/maven2/a-1.0.pom",
		},
		{
			name: "username without password is removed",
			url:  "https://user@repo.example.com/maven2/a-1.0.pom",
			want: "https://repo.example.com/maven2/a-1.0.pom",
		},
		{
			name: "query and fragment are removed",
			url:  "https://repo.example.com/maven2/a-1.0.pom?token=secret#frag",
			want: "https://repo.example.com/maven2/a-1.0.pom",
		},
		{
			name: "empty query is removed",
			url:  "https://repo.example.com/maven2/a-1.0.pom?",
			want: "https://repo.example.com/maven2/a-1.0.pom",
		},
		{
			name: "port is kept",
			url:  "http://user:pass@127.0.0.1:8081/maven2/?token=secret",
			want: "http://127.0.0.1:8081/maven2/",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			require.NoError(t, err)
			require.Equal(t, tt.want, displayURL(*u))
		})
	}
}
