package scan

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/liamg/tml"
)

const (
	formatKeyword         = "<lightblue>"
	formatSymbol          = "<lightblue>"
	formatBrace           = "<lightgrey>"
	formatBracket         = "<lightgrey>"
	formatMarker          = "<italic><lightmagenta>"
	formatString          = "<lightyellow>"
	formatMultilineString = "<lightmagenta>"
	formatComment         = "<darkgrey>"
)

func highlight(filename string, inputLines []Line) []Line {
	switch strings.ToLower(filepath.Ext(filename)) {
	case ".tf":
		return highlightHCL(inputLines)
	}
	return highlightDefault(inputLines)
}

func highlightDefault(inputLines []Line) []Line {
	var output []Line
	for _, line := range inputLines {
		line.Highlighted = line.Content
		output = append(output, line)
	}
	return output
}

// nolint
func highlightHCL(inputLines []Line) []Line {
	var output []Line
	var inComment, inMultilineComment, inString, inMultilineString, inAssignment, inEOLMarker, inTemplate, dollared bool

	var blockDepth int
	var currentEOL string
	var format string
	var foundFirstCause bool
	maxCause := -1
	for i, line := range inputLines {
		highlighted := ""
		inEOLMarker = false
		inAssignment = false
		inString = false
		inTemplate = false
		inComment = false
		format = ""

		switch {
		case line.Truncated:
			line.Highlighted = tml.Sprintf("  <italic><dim>...")
		case currentEOL != "" && line.Content == currentEOL:
			currentEOL = ""
			inMultilineString = false
			line.Highlighted = tml.Sprintf(formatMarker+"%s", line.Content)
		default:

			lastC := rune(0)
			peekC := rune(0)

			for i, c := range line.Content {

				if i+1 < len([]rune(line.Content))-1 {
					peekC = []rune(line.Content)[i+1]
				} else {
					peekC = 0
				}

				if inAssignment {
					switch c {
					case ' ', '\t':
					case '<':
						inEOLMarker = true
						format += formatMarker
						inAssignment = false
					default:
						inAssignment = false
					}
				}

				switch {
				case inComment:
				case inMultilineComment:
					switch c {
					case '*':
						if peekC == '/' {
							inMultilineComment = false
						}
					}
				case inString && !inTemplate:
					format += formatString
					switch c {
					case '{':
						if dollared {
							inTemplate = true
							format += formatBrace
						}
					case '"':
						inString = false
					default:
					}
					dollared = c == '$' && lastC != '\\'
					if dollared {
						format += formatBrace
					}
				case inMultilineString:
					format += formatMultilineString
				case inEOLMarker:
					currentEOL += string(c)
				default:
					switch c {
					case '"':
						inString = true
						dollared = false
						format += formatString
					case '{':
						format += formatBrace
						blockDepth++
					case '}':
						format += formatBrace
						if !inTemplate {
							blockDepth--
						}
						inTemplate = false
					case '[', ']', '(', ')':
						format += formatBracket
					case '=':
						inAssignment = true
						format += formatSymbol
					case '.', ',', '+', '-', '*':
						format += formatSymbol
					case '#':
						inComment = true
						format += formatComment
					case '/':
						switch {
						case peekC == '/':
							inComment = true
							format += formatComment
						case peekC == '*':
							inMultilineComment = true
							format += formatComment
						default:
							format += formatSymbol
						}
					case ' ', '\t':
					default:
						format = ""
						if blockDepth == 0 {
							format += formatKeyword
						}
						inAssignment = false
					}

				}
				if format != "" {
					highlighted += tml.Sprintf(fmt.Sprintf("%s%%c", format), c)
				} else {
					highlighted += string(c)
				}

				lastC = c
			}

			line.Highlighted = highlighted
		}

		if inEOLMarker && len(currentEOL) > 2 {
			currentEOL = currentEOL[2:]
			inMultilineString = true
		}

		if line.IsCause {
			maxCause = i
		}
		line.FirstCause = !foundFirstCause && line.IsCause
		if line.FirstCause {
			foundFirstCause = true
		}

		output = append(output, line)
	}
	if maxCause > -1 {
		output[maxCause].LastCause = true
	}
	return output
}
