// Ported from https://github.com/golang/go/blob/e9c96835971044aa4ace37c7787de231bbde05d9/src/cmd/go/internal/version/version.go

package binary

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

var ErrNonGoBinary = xerrors.New("non go binary")

// Parse scans file to try to report the Go and module versions.
func Parse(r dio.ReadSeekerAt) ([]types.Library, error) {
	x, err := openExe(r)
	if err != nil {
		return nil, err
	}

	vers, mod := findVers(x)
	if vers == "" {
		return nil, ErrNonGoBinary
	}

	var libs []types.Library
	scanner := bufio.NewScanner(strings.NewReader(mod))
	for scanner.Scan() {
		line := scanner.Text()
		ss := strings.Fields(line)

		// Since we only use "dep" and "=>" which are both at least 3 column, skip if
		// length is shorter.
		if len(ss) < 3 {
			continue
		}

		switch ss[0] {
		case "dep":
			libs = append(libs, types.Library{
				Name:    ss[1],
				Version: ss[2],
			})
		case "=>":
			// replace replaces the previous entry
			if len(libs) == 0 {
				return nil, errors.New("replace directive without prior dependency declaration")
			}
			prev := len(libs) - 1
			libs[prev] = types.Library{
				Name:    ss[1],
				Version: ss[2],
			}
		default:
			continue
		}
	}

	return libs, nil
}

// The build info blob left by the linker is identified by
// a 16-byte header, consisting of buildInfoMagic (14 bytes),
// the binary's pointer size (1 byte),
// and whether the binary is big endian (1 byte).
var buildInfoMagic = []byte("\xff Go buildinf:")

// findVers finds and returns the Go version and module version information
// in the executable x.
func findVers(x exe) (vers, mod string) {
	// Read the first 64kB of text to find the build info blob.
	text := x.DataStart()
	data, err := x.ReadData(text, 64*1024)
	if err != nil {
		return
	}
	for ; !bytes.HasPrefix(data, buildInfoMagic); data = data[32:] {
		if len(data) < 32 {
			return
		}
	}

	// Decode the blob.
	ptrSize := int(data[14])
	bigEndian := data[15] != 0
	var bo binary.ByteOrder
	if bigEndian {
		bo = binary.BigEndian
	} else {
		bo = binary.LittleEndian
	}
	var readPtr func([]byte) uint64
	if ptrSize == 4 {
		readPtr = func(b []byte) uint64 { return uint64(bo.Uint32(b)) }
	} else {
		readPtr = bo.Uint64
	}
	vers = readString(x, ptrSize, readPtr, readPtr(data[16:]))
	if vers == "" {
		return
	}
	mod = readString(x, ptrSize, readPtr, readPtr(data[16+ptrSize:]))
	if len(mod) >= 33 && mod[len(mod)-17] == '\n' {
		// Strip module framing.
		mod = mod[16 : len(mod)-16]
	} else {
		mod = ""
	}
	return
}

// readString returns the string at address addr in the executable x.
func readString(x exe, ptrSize int, readPtr func([]byte) uint64, addr uint64) string {
	hdr, err := x.ReadData(addr, uint64(2*ptrSize))
	if err != nil || len(hdr) < 2*ptrSize {
		return ""
	}
	dataAddr := readPtr(hdr)
	dataLen := readPtr(hdr[ptrSize:])
	data, err := x.ReadData(dataAddr, dataLen)
	if err != nil || uint64(len(data)) < dataLen {
		return ""
	}
	return string(data)
}
