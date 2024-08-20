package scan

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/alecthomas/chroma"
	"github.com/alecthomas/chroma/formatters"
	"github.com/alecthomas/chroma/lexers"
	"github.com/alecthomas/chroma/styles"
)

type cache struct {
	sync.RWMutex
	data map[string][]string
}

func (c *cache) Get(key string) ([]string, bool) {
	c.RLock()
	defer c.RUnlock()
	data, ok := c.data[key]
	return data, ok
}

func (c *cache) Set(key string, data []string) {
	c.Lock()
	defer c.Unlock()
	c.data[key] = data
}

var globalCache = &cache{
	data: make(map[string][]string),
}

func highlight(fsKey, filename string, startLine, endLine int, input, theme string) []string {

	key := fmt.Sprintf("%s|%s|%d-%d", fsKey, filename, startLine, endLine)
	if lines, ok := globalCache.Get(key); ok {
		return lines
	}

	lexer := lexers.Match(filename)
	if lexer == nil {
		lexer = lexers.Fallback
	}
	lexer = chroma.Coalesce(lexer)

	style := styles.Get(theme)
	if style == nil {
		style = styles.Fallback
	}
	formatter := formatters.Get("terminal256")
	if formatter == nil {
		formatter = formatters.Fallback
	}

	iterator, err := lexer.Tokenise(nil, input)
	if err != nil {
		return nil
	}

	var buffer bytes.Buffer
	if err := formatter.Format(&buffer, style, iterator); err != nil {
		return nil
	}

	raw := shiftANSIOverLineEndings(buffer.Bytes())
	lines := strings.Split(string(raw), "\n")
	globalCache.Set(key, lines)
	return lines
}

func shiftANSIOverLineEndings(input []byte) []byte {
	var output []byte
	prev := byte(0)
	inCSI := false
	csiShouldCarry := false
	var csi []byte
	var skipOutput bool
	for _, r := range input {
		skipOutput = false
		if !inCSI {
			switch {
			case r == '\n':
				if csiShouldCarry && len(csi) > 0 {
					skipOutput = true
					output = append(output, '\n')
					output = append(output, csi...)
					csi = nil
					csiShouldCarry = false
				}
			case r == '[' && prev == 0x1b:
				inCSI = true
				csi = append(csi, 0x1b, '[')
				output = output[:len(output)-1]
				skipOutput = true
			default:
				csiShouldCarry = false
				if len(csi) > 0 {
					output = append(output, csi...)
					csi = nil
				}
			}
		} else {
			csi = append(csi, r)
			skipOutput = true
			if r >= 0x40 && r <= 0x7E {
				csiShouldCarry = true
				inCSI = false
			}
		}
		if !skipOutput {
			output = append(output, r)
		}
		prev = r
	}

	return append(output, csi...)
}
