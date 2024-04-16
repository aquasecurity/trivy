package wordpress

import (
	"bufio"
	"io"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func Parse(r io.Reader) (lib types.Library, err error) {

	// If wordpress file, open file and
	// find line with content
	// $wp_version = '<WORDPRESS_VERSION>';

	var version string
	isComment := false
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		// Remove comment
		commentIndex := strings.Index(line, "//")
		if commentIndex != -1 {
			line = line[:commentIndex]
		}

		line = strings.TrimSpace(line)

		// Handle comment
		switch {
		case strings.HasPrefix(line, "/*"):
			isComment = true
			continue
		case isComment && strings.HasSuffix(line, "*/"):
			isComment = false
			continue
		case isComment:
			continue
		}

		// It might include $wp_version_something
		if !strings.HasPrefix(line, "$wp_version") {
			continue
		}

		ss := strings.Split(line, "=")
		if len(ss) != 2 || strings.TrimSpace(ss[0]) != "$wp_version" {
			continue
		}

		// Each variable must end with ";".
		end := strings.Index(ss[1], ";")
		if end == -1 {
			continue
		}

		// Remove ";" and white space.
		version = strings.TrimSpace(ss[1][:end])

		// Remove single and double quotes.
		version = strings.Trim(version, `'"`)

		break
	}

	if err = scanner.Err(); err != nil || version == "" {
		return types.Library{}, xerrors.New("version.php could not be parsed")
	}

	return types.Library{
		Name:    "wordpress",
		Version: version,
	}, nil
}
