package json

import (
	"bytes"
	"errors"
	"io"
)

// TokenType represents the type of token being processed
type TokenType int

const (
	TokenNormal TokenType = iota
	TokenString
	TokenSingleLineComment
	TokenMultiLineComment
)

// jsoncParser manages the state and processing of JSONC content
type jsoncParser struct {
	reader    *bytes.Reader // Source reader
	dst       []byte        // Destination buffer
	pos       int           // Current position in destination
	tokenType TokenType     // Current token type being processed
	escaped   bool          // Whether the previous character was an escape character
	lastChar  byte          // Last processed character
}

// ToRFC8259 converts JSONC (JSON with Comments) to valid JSON following RFC8259.
// It strips out comments and trailing commas while maintaining the exact character
// offsets as the input. This ensures that any JSON parser locations will map
// directly back to the original source file positions.
//
// Both line numbers and character positions are preserved in the output.
// Comments and trailing commas are replaced with spaces without changing line counts.
//
// Comments can be either:
// - Single-line: starting with // and continuing to the end of the line
// - Multi-line: starting with /* and ending with */
//
// Trailing commas are allowed in JSONC but not in standard JSON, so they are replaced
// with spaces to maintain character offsets.
func ToRFC8259(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src) // Copy input to maintain same length and offsets

	parser := newJSONCParser(src, dst)
	parser.process()

	return dst
}

// UnmarshalJSONC parses JSONC (JSON with Comments) data into the specified value.
// It first converts JSONC to standard JSON following RFC8259 and then unmarshals it.
// This is a convenience function that combines ToRFC8259 and Unmarshal.
//
// The parser preserves line number information, which is essential for reporting
// errors at their correct locations in the original file.
//
// Usage example:
//
//	type Config struct {
//	    Name    string            `json:"name"`
//	    Version string            `json:"version"`
//	    xjson.Location            // Embed Location to get line number info
//	}
//
//	var config Config
//	if err := xjson.UnmarshalJSONC(data, &config); err != nil {
//	    return err
//	}
func UnmarshalJSONC(data []byte, v any) error {
	jsonData := ToRFC8259(data)
	return Unmarshal(jsonData, v)
}

// newJSONCParser creates a new JSONC parser
func newJSONCParser(src, dst []byte) *jsoncParser {
	return &jsoncParser{
		reader:    bytes.NewReader(src),
		dst:       dst,
		pos:       0,
		tokenType: TokenNormal,
	}
}

// process processes the input JSONC content
func (p *jsoncParser) process() {
	for {
		b, err := p.reader.ReadByte()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			// Ignore other errors (not expected to occur)
			break
		}
		p.processChar(b)
	}
}

// processChar processes a single character based on current state
func (p *jsoncParser) processChar(b byte) {
	switch p.tokenType {
	case TokenString:
		p.processStringToken(b)
	case TokenSingleLineComment:
		p.processSingleLineComment(b)
	case TokenMultiLineComment:
		p.processMultiLineComment(b)
	default:
		p.processNormalToken(b)
	}
}

// processStringToken processes a character within a string literal
func (p *jsoncParser) processStringToken(b byte) {
	switch {
	case p.escaped:
		p.escaped = false
	case b == '\\':
		p.escaped = true
	case b == '"':
		p.tokenType = TokenNormal
	}

	p.lastChar = b
	p.pos++
}

// processSingleLineComment processes a character within a single-line comment
func (p *jsoncParser) processSingleLineComment(b byte) {
	if b == '\n' {
		// End of single-line comment at newline
		p.tokenType = TokenNormal
	} else if !isPreservedWhitespace(b) {
		// Replace non-whitespace characters with spaces
		if p.pos < len(p.dst) {
			p.dst[p.pos] = ' '
		}
	}

	p.lastChar = b
	p.pos++
}

// processMultiLineComment processes a character within a multi-line comment
func (p *jsoncParser) processMultiLineComment(b byte) {
	if p.lastChar == '*' && b == '/' {
		// End of multi-line comment
		p.tokenType = TokenNormal
		if p.pos < len(p.dst) {
			p.dst[p.pos] = ' ' // Replace '/' with space
		}
	} else if !isPreservedWhitespace(b) {
		// Replace non-whitespace with space
		if p.pos < len(p.dst) {
			p.dst[p.pos] = ' '
		}
	}

	p.lastChar = b
	p.pos++
}

// processNormalToken processes a character outside of string literals and comments
func (p *jsoncParser) processNormalToken(b byte) {
	switch b {
	case '"':
		// Start of string literal
		p.tokenType = TokenString
	case '/':
		// Potential start of comment - look ahead
		nextByte, err := p.reader.ReadByte()
		if err != nil {
			// End of file after '/' character
			return
		}

		switch nextByte {
		case '/':
			// Start of single-line comment
			p.tokenType = TokenSingleLineComment
			if p.pos < len(p.dst) {
				p.dst[p.pos] = ' ' // Replace '/' with space
			}
			if p.pos+1 < len(p.dst) {
				p.dst[p.pos+1] = ' ' // Replace second '/' with space
			}
			p.lastChar = nextByte
			p.pos += 2
			return
		case '*':
			// Start of multi-line comment
			p.tokenType = TokenMultiLineComment
			if p.pos < len(p.dst) {
				p.dst[p.pos] = ' ' // Replace '/' with space
			}
			if p.pos+1 < len(p.dst) {
				p.dst[p.pos+1] = ' ' // Replace '*' with space
			}
			p.lastChar = nextByte
			p.pos += 2
			return
		}

		// Not a comment, put the byte back
		p.reader.UnreadByte()
	case ']', '}':
		// Handle trailing comma - look backward
		p.handleTrailingComma()
	}
	p.lastChar = b
	p.pos++
}

// handleTrailingComma handles the trailing comma by looking backward from the current position
func (p *jsoncParser) handleTrailingComma() {
	// Start from one position before the current bracket
	startPos := p.pos - 1
	if startPos < 0 {
		return
	}

	// Find the previous significant (non-whitespace) character
	for i := startPos; i >= 0; i-- {
		if i >= len(p.dst) {
			continue
		}

		c := p.dst[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			// Skip whitespace
			continue
		case ',':
			// If it's a comma, replace it with a space
			p.dst[i] = ' '
		default:
			// Stop after finding the first non-whitespace character
			return
		}
	}
}

// isPreservedWhitespace returns true for whitespace that should be preserved
func isPreservedWhitespace(c byte) bool {
	return c == '\n' || c == '\t' || c == '\r'
}
