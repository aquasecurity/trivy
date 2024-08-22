package log

// DeferredLogger are needed to save logs and print them after calling `PrintLogs()` command.
// for example, this may be necessary when the logger is not yet initialized, but messages need to be transmitted
// in this case, the messages are saved and printed after the logger is initialized
var DeferredLogger deferredLogger

type deferredLogger struct {
	deferredLogs []deferredLog
}

type deferredLog struct {
	logFunc func(format string, args ...any)
	message string
	args    []any
}

func (d *deferredLogger) Debug(message string, args ...any) {
	d.deferredLogs = append(d.deferredLogs, deferredLog{
		logFunc: Debug,
		message: message,
		args:    args,
	})
}

func (d *deferredLogger) Info(message string, args ...any) {
	d.deferredLogs = append(d.deferredLogs, deferredLog{
		logFunc: Info,
		message: message,
		args:    args,
	})
}

func (d *deferredLogger) Warn(message string, args ...any) {
	d.deferredLogs = append(d.deferredLogs, deferredLog{
		logFunc: Warn,
		message: message,
		args:    args,
	})
}

func (d *deferredLogger) Error(message string, args ...any) {
	d.deferredLogs = append(d.deferredLogs, deferredLog{
		logFunc: Error,
		message: message,
		args:    args,
	})
}

func (d *deferredLogger) PrintLogs() {
	for _, l := range d.deferredLogs {
		l.logFunc(l.message, l.args...)
	}
	// Clear deferredLogs
	d.deferredLogs = nil
}
