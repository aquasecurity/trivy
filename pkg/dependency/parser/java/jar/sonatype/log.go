package sonatype

import "github.com/aquasecurity/trivy/pkg/log"

// logger implements LeveledLogger
// https://github.com/hashicorp/go-retryablehttp/blob/991b9d0a42d13014e3689dd49a94c02be01f4237/client.go#L285-L290
type logger struct{}

func (logger) Error(msg string, keysAndValues ...interface{}) {
	// Use Debugw to suppress errors on failure
	if msg == "request failed" {
		log.Logger.Debugw(msg, keysAndValues...)
		return
	}
	log.Logger.Errorw(msg, keysAndValues)
}

func (logger) Info(msg string, keysAndValues ...interface{}) {
	log.Logger.Infow(msg, keysAndValues...)
}

func (logger) Debug(msg string, keysAndValues ...interface{}) {
	// This message is displayed too much
	if msg == "performing request" {
		return
	}
	log.Logger.Debugw(msg, keysAndValues...)
}

func (logger) Warn(msg string, keysAndValues ...interface{}) {
	log.Logger.Warnw(msg, keysAndValues...)
}
