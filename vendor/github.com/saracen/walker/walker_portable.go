// +build appengine !linux,!darwin,!freebsd,!openbsd,!netbsd

package walker

import "os"

func (w *walker) readdir(dirname string) error {
	f, err := os.Open(dirname)
	if err != nil {
		return err
	}

	list, err := f.Readdir(-1)
	f.Close()
	if err != nil {
		return err
	}

	for _, fi := range list {
		if err = w.walk(dirname, fi); err != nil {
			return err
		}
	}
	return nil
}
