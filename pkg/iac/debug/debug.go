package debug

import (
	"fmt"
	"io"
	"strings"
	"time"
)

const timeFormat = "04:05.000000000"

type Logger struct {
	writer io.Writer
	prefix string
}

func New(w io.Writer, parts ...string) Logger {
	return Logger{
		writer: w,
		prefix: strings.Join(parts, "."),
	}
}

func (l *Logger) Extend(parts ...string) Logger {
	return Logger{
		writer: l.writer,
		prefix: strings.Join(append([]string{l.prefix}, parts...), "."),
	}
}

func (l *Logger) Log(format string, args ...any) {
	if l.writer == nil {
		return
	}
	message := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s %-32s %s\n", time.Now().Format(timeFormat), l.prefix, message)
	_, _ = l.writer.Write([]byte(line))
}
