package log

import (
	"go.uber.org/zap"
)

var Logger *zap.SugaredLogger

func init() {
	if logger, err := zap.NewProduction(); err == nil {
		Logger = logger.Sugar()
	}
}

func SetLogger(l *zap.SugaredLogger) {
	Logger = l
}
