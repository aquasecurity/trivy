package dpkg

import (
	"bufio"
	"bytes"
	"io"
	"net/textproto"
	"strings"
)

type dpkgScanner struct {
	*bufio.Scanner
}

// NewScanner returns a new scanner that splits on empty lines.
func NewScanner(r io.Reader) *dpkgScanner {
	s := bufio.NewScanner(r)
	s.Split(emptyLineSplit)
	return &dpkgScanner{Scanner: s}
}

// Scan advances the scanner to the next token.
func (s *dpkgScanner) Scan() bool {
	return s.Scanner.Scan()
}

// Header returns the MIME header of the current scan.
func (s *dpkgScanner) Header() (textproto.MIMEHeader, error) {
	b := s.Bytes()
	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(b)))
	return reader.ReadMIMEHeader()
}

// emptyLineSplit is a bufio.SplitFunc that splits on empty lines.
func emptyLineSplit(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}

	if i := strings.Index(string(data), "\n\n"); i >= 0 {
		// We have a full empty line terminated block.
		return i + 2, data[0:i], nil
	}

	if atEOF {
		// Return the rest of the data if we're at EOF.
		return len(data), data, nil
	}

	return
}
