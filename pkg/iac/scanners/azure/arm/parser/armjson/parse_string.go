package armjson

import (
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/types"
)

var escapes = map[rune]string{
	'\\': "\\",
	'/':  "/",
	'"':  "\"",
	'n':  "\n",
	'r':  "\r",
	'b':  "\b",
	'f':  "\f",
	't':  "\t",
}

// nolint: cyclop
func (p *parser) parseString(parentMetadata *types.Metadata) (Node, error) {

	n, _ := p.newNode(KindString, parentMetadata)

	b, err := p.next()
	if err != nil {
		return nil, err
	}

	if b != '"' {
		return nil, p.makeError("expecting string delimiter")
	}

	var sb strings.Builder

	var inEscape bool
	var inHex bool
	var hex []rune

	for {
		c, err := p.next()
		if err != nil {
			return nil, err
		}
		// nolint: gocritic
		if inHex {
			switch {
			case c >= 'a' && c <= 'f', c >= 'A' && c <= 'F', c >= '0' && c <= '9':
				hex = append(hex, c)
				if len(hex) == 4 {
					inHex = false
					char, err := strconv.Unquote("\\u" + string(hex))
					if err != nil {
						return nil, p.makeError("invalid unicode character '%s'", err)
					}
					sb.WriteString(char)
					hex = nil
				}
			default:
				return nil, p.makeError("invalid hexedecimal escape sequence '\\%s%c'", string(hex), c)
			}
		} else if inEscape {
			inEscape = false
			if c == 'u' {
				inHex = true
				continue
			}
			seq, ok := escapes[c]
			if !ok {
				return nil, p.makeError("invalid escape sequence '\\%c'", c)
			}
			sb.WriteString(seq)
		} else {
			switch c {
			case '\\':
				inEscape = true
			case '"':
				n.raw = sb.String()
				n.end = p.position
				return n, nil
			default:
				if c < 0x20 || c > 0x10FFFF {
					return nil, p.makeError("invalid unescaped character '0x%X'", c)
				}
				sb.WriteRune(c)
			}
		}

	}
}
