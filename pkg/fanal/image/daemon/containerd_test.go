//go:build !windows

// The containerd image source is only reachable on Linux, where the containerd
// client dials a unix socket. A Windows test server would need a named pipe
// listener, which would pull github.com/Microsoft/go-winio in as a direct
// dependency.

package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	imagesapi "github.com/containerd/containerd/api/services/images/v1"
	descriptorpb "github.com/containerd/containerd/api/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	xos "github.com/aquasecurity/trivy/pkg/x/os"
)

// fakeImagesService is a minimal containerd Images service. It always reports a
// single image, which is all ContainerdImage needs to get past ListImages.
type fakeImagesService struct {
	imagesapi.UnimplementedImagesServer
}

func (fakeImagesService) List(context.Context, *imagesapi.ListImagesRequest) (*imagesapi.ListImagesResponse, error) {
	return &imagesapi.ListImagesResponse{
		Images: []*imagesapi.Image{
			{
				Name: "alpine:3.11",
				Target: &descriptorpb.Descriptor{
					MediaType: "application/vnd.oci.image.index.v1+json",
					Digest:    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
					Size:      1,
				},
			},
		},
	}, nil
}

// connTracker records every connection accepted from the containerd client and
// reports whether all of them were closed by the peer. A closed gRPC client
// drops its connection, and the next read or write on the server side fails.
type connTracker struct {
	net.Listener

	mu     sync.Mutex
	closed []bool
}

func (l *connTracker) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	l.mu.Lock()
	idx := len(l.closed)
	l.closed = append(l.closed, false)
	l.mu.Unlock()

	return &trackedConn{Conn: conn, tracker: l, idx: idx}, nil
}

func (l *connTracker) allClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.closed) == 0 {
		return false
	}
	for _, closed := range l.closed {
		if !closed {
			return false
		}
	}
	return true
}

func (l *connTracker) markClosed(idx int) {
	l.mu.Lock()
	l.closed[idx] = true
	l.mu.Unlock()
}

// trackedConn marks its connection as closed once any I/O on it fails, which is
// what happens when the peer closes the connection.
type trackedConn struct {
	net.Conn

	tracker *connTracker
	idx     int
}

func (c *trackedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.check(err)
	return n, err
}

func (c *trackedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.check(err)
	return n, err
}

func (c *trackedConn) check(err error) {
	if err == nil {
		return
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return
	}
	c.tracker.markClosed(c.idx)
}

// startFakeContainerd serves the containerd Images API on a unix socket and
// points CONTAINERD_ADDRESS at it, so ContainerdImage talks to this test server
// instead of a real containerd daemon.
func startFakeContainerd(t *testing.T) *connTracker {
	t.Helper()

	dir, err := os.MkdirTemp("", "ctrd") //nolint:usetesting // t.TempDir() paths can be too long for socket binding
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	lis, err := net.Listen("unix", filepath.Join(dir, "containerd.sock"))
	require.NoError(t, err)
	tracker := &connTracker{Listener: lis}
	t.Cleanup(func() { _ = tracker.Close() })

	srv := grpc.NewServer()
	imagesapi.RegisterImagesServer(srv, fakeImagesService{})
	go func() { _ = srv.Serve(tracker) }()
	t.Cleanup(srv.Stop)

	t.Setenv("CONTAINERD_ADDRESS", filepath.Join(dir, "containerd.sock"))
	return tracker
}

// breakCreateTemp makes xos.CreateTemp fail deterministically by replacing the
// process-specific temp directory with a regular file. It returns a function
// that restores the directory, because xos caches that path for the process.
func breakCreateTemp(t *testing.T) func() {
	t.Helper()

	tempDir := xos.TempDir()
	require.NoError(t, os.RemoveAll(tempDir))
	require.NoError(t, os.WriteFile(tempDir, []byte("not a directory"), 0o600))

	return func() {
		_ = os.Remove(tempDir)
		_ = os.MkdirAll(tempDir, 0o700)
	}
}

// TestContainerdImage_CreateTempErrorClosesClient pins the error path between
// client.New and the temporary file. NewContainerImage drops the cleanup function it
// gets back when it returns an error, so ContainerdImage has to close the client
// itself before returning; the cleanup function is deliberately not called here.
func TestContainerdImage_CreateTempErrorClosesClient(t *testing.T) {
	tracker := startFakeContainerd(t)

	restore := breakCreateTemp(t)
	defer restore()

	img, cleanup, err := ContainerdImage(t.Context(), "alpine:3.11", types.ImageOptions{})

	require.Error(t, err)
	assert.ErrorContains(t, err, "failed to create a temporary file")
	assert.Nil(t, img)
	_ = cleanup // a failing ContainerdImage never hands the caller a chance to use it

	// The client opened one connection for ListImages. If the error path did not close
	// the client, that connection is still open.
	assert.Eventually(t, tracker.allClosed, 5*time.Second, 50*time.Millisecond,
		"the containerd client was not closed after xos.CreateTemp failed")
}

// tempDirEntries lists the names in dir so a test can compare it before and after.
func tempDirEntries(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// TestContainerdImage_InspectErrorClosesClientAndRemovesTempFile covers the error path
// after the temporary file exists. The fake server implements List only, so reading the
// image config inside inspect fails; both the client and the temporary file have to be
// released before that error is returned.
func TestContainerdImage_InspectErrorClosesClientAndRemovesTempFile(t *testing.T) {
	tracker := startFakeContainerd(t)
	tempDir := xos.TempDir()
	before := tempDirEntries(t, tempDir)

	img, cleanup, err := ContainerdImage(t.Context(), "alpine:3.11", types.ImageOptions{})

	require.Error(t, err)
	assert.ErrorContains(t, err, "inspect error")
	assert.Nil(t, img)
	_ = cleanup // a failing ContainerdImage never hands the caller a chance to use it

	assert.Eventually(t, tracker.allClosed, 5*time.Second, 50*time.Millisecond,
		"the containerd client was not closed after inspect failed")

	assert.ElementsMatch(t, before, tempDirEntries(t, tempDir),
		"the temporary file was left behind after inspect failed")
}
