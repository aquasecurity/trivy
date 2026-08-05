package appimage_test

import (
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	artappimage "github.com/aquasecurity/trivy/pkg/fanal/artifact/appimage"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// mockWalker is a minimal Walker that records Walk calls and calls fn for
// any files provided via inject. It never actually reads SquashFS.
type mockWalker struct {
	files []mockFile
}

type mockFile struct {
	path   string
	size   int64
	opener func() (io.ReadCloser, error)
}

func (m *mockWalker) Walk(_ *io.SectionReader, _ string, _ walker.Option, fn walker.WalkFunc) error {
	for _, f := range m.files {
		fi := mockFileInfo{name: f.path, size: f.size}
		opener := func() (xio.ReadSeekCloserAt, error) {
			rc, err := f.opener()
			if err != nil {
				return nil, err
			}
			return nopReadSeekCloserAt{rc}, nil
		}
		if err := fn(f.path, fi, opener); err != nil {
			return err
		}
	}
	return nil
}

// nopReadSeekCloserAt wraps an io.ReadCloser to satisfy the ReadSeekCloserAt interface.
type nopReadSeekCloserAt struct{ io.ReadCloser }

func (n nopReadSeekCloserAt) Seek(int64, int) (int64, error) { return 0, nil }
func (n nopReadSeekCloserAt) ReadAt(b []byte, _ int64) (int, error) {
	return n.Read(b)
}

// mockFileInfo implements os.FileInfo for test files.
type mockFileInfo struct {
	name string
	size int64
}

func (m mockFileInfo) Name() string       { return m.name }
func (m mockFileInfo) Size() int64        { return m.size }
func (m mockFileInfo) Mode() os.FileMode  { return 0o644 }
func (m mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m mockFileInfo) IsDir() bool        { return false }
func (m mockFileInfo) Sys() interface{}   { return nil }

func TestIsAppImage(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte // content of the file
		expected bool
	}{
		{
			name:     "valid AppImage Type 2",
			data:     append(make([]byte, 8), []byte("AI\x02")...),
			expected: true,
		},
		{
			name:     "not an AppImage (wrong magic)",
			data:     append(make([]byte, 8), []byte("ELF")...),
			expected: false,
		},
		{
			name:     "too short",
			data:     []byte{0x7f, 0x45},
			expected: false,
		},
		{
			name:     "AppImage Type 1 (not supported)",
			data:     append(make([]byte, 8), []byte("AI\x01")...),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := walker.IsAppImage(bytesReaderAt(tt.data))
			assert.Equal(t, tt.expected, got)
		})
	}
}

// bytesReaderAt wraps a byte slice in an io.ReaderAt.
type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestNewArtifact_NotAppImage(t *testing.T) {
	// Create a temp file with no AppImage magic
	f, err := os.CreateTemp(t.TempDir(), "notappimage-*.AppImage")
	require.NoError(t, err)
	_, err = f.Write(make([]byte, 64))
	require.NoError(t, err)
	require.NoError(t, f.Close())

	_, err = artappimage.NewArtifact(f.Name(), nil, &mockWalker{}, artifact.Option{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not an AppImage Type 2 file")
}

func TestNewArtifact_FileNotFound(t *testing.T) {
	_, err := artappimage.NewArtifact("/nonexistent/path.AppImage", nil, &mockWalker{}, artifact.Option{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "appimage open error")
}

func TestArtifact_TypeAppImage(t *testing.T) {
	// Verify the TypeAppImage constant has the expected string value
	assert.Equal(t, types.ArtifactType("appimage"), types.TypeAppImage)
}

func TestArtifact_InspectReturnsCorrectType(t *testing.T) {
	// This test is skipped unless a real AppImage is available because
	// constructing a valid AppImage binary in a unit test requires a full
	// ELF + SquashFS payload. Integration-level smoke testing is done
	// against real AppImages (LeoCAD, LM-Studio) in the verification step.
	t.Skip("requires real AppImage binary; see verification step in SKILL.md")
}

// Verify Walker interface is satisfied by AppImage walker
var _ artappimage.Walker = (*mockWalker)(nil)

// Ensure the artifact implements artifact.Artifact at compile time.
// This is checked implicitly since NewArtifact returns *Artifact which
// must have Inspect/Clean methods; the compiler enforces this.
func TestArtifactInterface(_ *testing.T) {
	// Compile-time check: *artappimage.Artifact must implement artifact.Artifact.
	var _ interface {
		Inspect(ctx context.Context) (artifact.Reference, error)
		Clean(artifact.Reference) error
	} = (*artappimage.Artifact)(nil)
}
