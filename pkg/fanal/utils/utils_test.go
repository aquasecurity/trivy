package utils

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"
)

func TestIsGzip(t *testing.T) {
	var tests = []struct {
		in   string
		want bool
	}{
		{filepath.Join("testdata", "test.txt.gz"), true},
		{filepath.Join("testdata", "test.tar.gz"), true},
		{filepath.Join("testdata", "test.txt"), false},
		{filepath.Join("testdata", "test.txt.zst"), false},
		{filepath.Join("testdata", "aqua.png"), false},
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
