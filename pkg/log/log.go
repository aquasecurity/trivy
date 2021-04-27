package log

import (
	"go.uber.org/zap"
)

var Logger *zap.SugaredLogger

func init() {
	config := zap.Config{
		Level:            zap.NewAtomicLevelAt(zap.DebugLevel),
		Development:      false,
		Encoding:         "console",
		EncoderConfig:    zap.NewDevelopmentEncoderConfig(),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}
	logger, _ := config.Build()
	Logger = logger.Sugar()
}

func SetLogger(l *zap.SugaredLogger) {
	Logger = l
}
