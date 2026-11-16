package node

import (
	"bufio"
	"context"
	"debug/elf"
	"errors"
	"io"
	"regexp"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// binaryParser reads Node's inspector product string without executing image code.
// Node's src/inspector_socket_server.cc builds this string from NODE_VERSION.
// Unlike development headers, it is retained in distroless Node images.
type binaryParser struct{}

var nodeProductVersion = regexp.MustCompile(`^node\.js/v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$`)

func (binaryParser) Parse(ctx context.Context, input xio.ReadSeekerAt) ([]types.Package, []types.Dependency, error) {
	binary, err := elf.NewFile(input)
	if err != nil {
		return nil, nil, nil
	}
	section := binary.Section(".rodata")
	if section == nil {
		return nil, nil, nil
	}
	reader := bufio.NewReaderSize(section.Open(), 64*1024)
	var version string
	var continued bool
	var bytesRead uint64
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		value, err := reader.ReadSlice(0)
		bytesRead += uint64(len(value))
		if err == nil && !continued {
			if match := nodeProductVersion.FindSubmatch(value[:len(value)-1]); match != nil {
				candidate := string(match[1])
				// Conflicting product strings are not reliable version evidence.
				if version != "" && version != candidate {
					return nil, nil, nil
				}
				version = candidate
			}
		}
		// Skip the rest of an oversized string instead of accepting a product
		// string that is only a suffix of an unrelated token.
		if errors.Is(err, bufio.ErrBufferFull) {
			continued = true
			continue
		}
		continued = false
		if errors.Is(err, io.EOF) {
			if bytesRead != section.Size {
				return nil, nil, io.ErrUnexpectedEOF
			}
			break
		}
		if err != nil {
			return nil, nil, err
		}
	}
	if version == "" {
		return nil, nil, nil
	}
	return []types.Package{{ID: dependency.ID(types.Node, "node", version), Name: "node", Version: version}}, nil, nil
}
