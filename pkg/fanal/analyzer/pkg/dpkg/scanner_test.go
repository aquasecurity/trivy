package dpkg

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanner(t *testing.T) {
	line := " /etc/big.conf 0123456789abcdef0123456789abcdef\n"
	conffiles := strings.Repeat(line, 128*1024/len(line)+1)
	input := "Package: a\n\nPackage: big\nConffiles:\n" + conffiles + "Description: test\n\nPackage: c\n"

	var got []string
	s := NewScanner(strings.NewReader(input))
	for s.Scan() {
		header, err := s.Header()
		if !errors.Is(err, io.EOF) {
			require.NoError(t, err)
		}
		got = append(got, header.Get("Package"))
	}
	require.NoError(t, s.Err())
	assert.Equal(t, []string{"a", "big", "c"}, got)
}
