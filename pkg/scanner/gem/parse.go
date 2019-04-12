package gem

import (
	"bufio"
	"strings"

	"github.com/knqyf263/trivy/pkg/types"
)

func (g *Scanner) ParseLockfile() ([]types.Library, error) {
	var libs []types.Library
	scanner := bufio.NewScanner(g.file)
	for scanner.Scan() {
		line := scanner.Text()
		if countLeadingSpace(line) == 4 {
			line = strings.TrimSpace(line)
			s := strings.Fields(line)
			if len(s) != 2 {
				continue
			}
			libs = append(libs, types.Library{
				Name:    s[0],
				Version: strings.Trim(s[1], "()"),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return libs, nil
}

func countLeadingSpace(line string) int {
	i := 0
	for _, runeValue := range line {
		if runeValue == ' ' {
			i++
		} else {
			break
		}
	}
	return i
}
