package memoryfs

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"sync"
	"time"
)

type file struct {
	sync.RWMutex
	info    fileinfo
	opener  LazyOpener
	content []byte
}

type fileAccess struct {
	file   *file
	reader io.Reader
}


// LazyOpener provides an io.Reader that can be used to access the content of a file, whatever the actual storage medium.
// If the LazyOpener returns an io.ReadCloser, it will be closed after each read.
type LazyOpener func() (io.Reader, error)

const bufferSize = 0x100

func (f *file) overwrite(data []byte, perm fs.FileMode) error {

	f.RLock()
	if f.opener == nil {
		f.RUnlock()
		return fmt.Errorf("missing opener")
	}
	f.RUnlock()

	rw, err := f.open()
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}

	f.Lock()
	f.info.size = int64(len(data))
	f.info.modified = time.Now()
	f.info.mode = perm
	f.Unlock()

	for len(data) > 0 {
		n, err := rw.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}

	return nil
}

func (f *file) stat() fs.FileInfo {
	f.RLock()
	defer f.RUnlock()
	return f.info
}

func (f *file) open() (*fileAccess, error) {
	f.RLock()
	defer f.RUnlock()
	if f.opener == nil {
		return nil, fmt.Errorf("missing opener")
	}
	return &fileAccess{
		file: f,
	}, nil
}

func (f *fileAccess) Stat() (fs.FileInfo, error) {
	f.file.RLock()
	defer f.file.RUnlock()
	return f.file.info, nil
}

func (f *fileAccess) Read(data []byte) (int, error) {
	r, err := func() (io.Reader, error) {
		f.file.Lock()
		defer f.file.Unlock()
		if f.reader == nil {
			r, err := f.file.opener()
			if err != nil {
				return nil, fmt.Errorf("failed to read file: %w", err)
			}
			f.reader = r
		}
		return f.reader, nil
	}()
	if err != nil {
		return 0, err
	}
	return r.Read(data)
}

func (f *fileAccess) Close() error {
	f.file.Lock()
	defer f.file.Unlock()
	if f.reader == nil {
		return nil
	}
	if closer, ok := f.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (f *fileAccess) Write(p []byte) (n int, err error) {
	w, err := func() (io.Writer, error) {
		f.file.Lock()
		defer f.file.Unlock()
		if f.reader == nil {
			r, err := f.file.opener()
			if err != nil {
				return nil, fmt.Errorf("failed to read file: %w", err)
			}
			f.reader = r
		}
		w, ok := f.reader.(io.Writer)
		if !ok {
			return nil, fmt.Errorf("cannot write - opener did not provide io.Writer")
		}
		return w, nil
	}()
	if err != nil {
		return 0, err
	}
	return w.Write(p)
}

type lazyAccess struct {
	file   *file
	reader io.Reader
	writer *bytes.Buffer
}

func (l *lazyAccess) Read(data []byte) (int, error) {
	l.file.RLock()
	defer l.file.RUnlock()
	if l.reader == nil {
		l.reader = bytes.NewReader(l.file.content)
	}
	return l.reader.Read(data)
}

func (l *lazyAccess) Write(data []byte) (int, error) {
	l.file.Lock()
	defer l.file.Unlock()
	if l.writer == nil {
		l.writer = bytes.NewBuffer(l.file.content)
		l.writer.Reset()
	}
	n, err := l.writer.Write(data)
	if err != nil {
		return 0, err
	}
	l.file.content = l.writer.Bytes()
	return n, nil
}
