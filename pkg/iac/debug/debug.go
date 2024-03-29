package debug

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
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

func (l *Logger) Log(format string, args ...interface{}) {
	if l.writer == nil {
		return
	}
	message := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s %-32s %s\n", time.Now().Format(timeFormat), l.prefix, message)
	_, _ = l.writer.Write([]byte(line))
}

func LogSystemInfo(w io.Writer, appVersion string) {
	if w == nil {
		return
	}
	sys := New(w, "system", "info")
	var appName string
	if path, err := os.Executable(); err != nil {
		if len(os.Args) > 0 {
			appName = os.Args[0]
		}
	} else {
		appName = filepath.Base(path)
	}

	wd, _ := os.Getwd()
	hostname, _ := os.Hostname()

	var inDocker bool
	if _, err := os.Stat("/.dockerenv"); err == nil || !os.IsNotExist(err) {
		inDocker = true
	}

	var kernelInfo string
	if data, err := os.ReadFile("/proc/version"); err == nil {
		kernelInfo = strings.TrimSpace(string(data))
	}

	sys.Log("APP       %s", appName)
	sys.Log("VERSION   %s", appVersion)
	sys.Log("OS        %s", runtime.GOOS)
	sys.Log("ARCH      %s", runtime.GOARCH)
	sys.Log("KERNEL    %s", kernelInfo)
	sys.Log("TERM      %s", os.Getenv("TERM"))
	sys.Log("SHELL     %s", os.Getenv("SHELL"))
	sys.Log("GOVERSION %s", runtime.Version())
	sys.Log("GOROOT    %s", runtime.GOROOT())
	sys.Log("CGO       %t", cgoEnabled)
	sys.Log("CPUCOUNT  %d", runtime.NumCPU())
	sys.Log("MAXPROCS  %d", runtime.GOMAXPROCS(0))
	sys.Log("WORKDIR   %s", wd)
	sys.Log("UID       %d", os.Getuid())
	sys.Log("EUID      %d", os.Geteuid())
	sys.Log("DOCKER    %t", inDocker)
	sys.Log("CI        %t", os.Getenv("CI") != "")
	sys.Log("HOSTNAME  %s", hostname)
	sys.Log("TEMP      %s", os.TempDir())
	sys.Log("PATHSEP   %c", filepath.Separator)
	sys.Log("CMD       %s", strings.Join(os.Args, " "))
}
