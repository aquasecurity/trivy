// +build linux darwin freebsd openbsd netbsd
// +build !appengine

package walker

import (
	"os"
	"syscall"
)

func (w *walker) readdir(dirname string) error {
	fd, err := syscall.Open(dirname, 0, 0)
	if err != nil {
		return &os.PathError{Op: "open", Path: dirname, Err: err}
	}
	defer syscall.Close(fd)

	buf := make([]byte, 8<<10)
	names := make([]string, 0, 100)

	nbuf := 0
	bufp := 0
	for {
		if bufp >= nbuf {
			bufp = 0
			nbuf, err = syscall.ReadDirent(fd, buf)
			if err != nil {
				return err
			}
			if nbuf <= 0 {
				return nil
			}
		}

		consumed, count, names := syscall.ParseDirent(buf[bufp:nbuf], 100, names[0:])
		bufp += consumed

		for _, name := range names[:count] {
			fi, err := os.Lstat(dirname + "/" + name)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			if err = w.walk(dirname, fi); err != nil {
				return err
			}
		}
	}
	return nil
}
