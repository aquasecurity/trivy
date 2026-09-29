package dpkg

import (
	"bufio"
	"bytes"
	"io"
	"net/textproto"
)

type dpkgScanner struct {
	*bufio.Scanner
}

// NewScanner returns a new scanner that splits on empty lines.
func NewScanner(r io.Reader) *dpkgScanner {
	s := bufio.NewScanner(r)
	// Package data may exceed default buffer size
	// Increase the buffer default size by 2 times
	buf := make([]byte, 0, 128*1024)
	s.Buffer(buf, 128*1024)

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

	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		// We have a full empty line terminated block.
		return i + 2, data[0:i], nil
	}

	if atEOF {
		// Return the rest of the data if we're at EOF.
		return len(data), data, nil
	}

	return
}
