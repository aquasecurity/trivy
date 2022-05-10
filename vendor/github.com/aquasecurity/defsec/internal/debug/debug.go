package debug

import (
	"fmt"
	"io"
	"time"
)

type Logger struct {
	writer io.Writer
	prefix string
}

func New(w io.Writer, prefix string) Logger {
	return Logger{
		writer: w,
		prefix: prefix,
	}
}

func (l *Logger) Log(format string, args ...interface{}) {
	if l.writer == nil {
		return
	}
	message := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s:%s] %s\n", l.prefix, time.Now().Format(time.StampMilli), message)
	_, _ = l.writer.Write([]byte(line))
}
