package gem

import (
	"bufio"
	"os"
	"strings"

	"github.com/knqyf263/trivy/pkg/types"
)

func ParseLockfile(f *os.File) ([]types.Library, error) {
	scanner := bufio.NewScanner(f)
	libs := []types.Library{}
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
