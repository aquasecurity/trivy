package testcontainers

// StdoutLog is the log type for STDOUT
const StdoutLog = "STDOUT"

// StderrLog is the log type for STDERR
const StderrLog = "STDERR"

// Log represents a message that was created by a process,
// LogType is either "STDOUT" or "STDERR",
// Content is the byte contents of the message itself
type Log struct {
	LogType string
	Content []byte
}

// LogConsumer represents any object that can
// handle a Log, it is up to the LogConsumer instance
// what to do with the log
type LogConsumer interface {
	Accept(Log)
}
