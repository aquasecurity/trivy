package utils

import (
	"bufio"
	"os"
	"testing"
)

func TestIsGzip(t *testing.T) {
	var tests = []struct {
		in   string
		want bool
	}{
		{"testdata/test.txt.gz", true},
		{"testdata/test.tar.gz", true},
		{"testdata/test.txt", false},
		{"testdata/test.txt.zst", false},
		{"testdata/aqua.png", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			f, err := os.Open(tt.in)
			if err != nil {
				t.Fatalf("unknown error: %s", err)
			}

			got := IsGzip(bufio.NewReader(f))
			if got != tt.want {
				t.Errorf("got %t, want %t", got, tt.want)
			}
		})
	}
}
