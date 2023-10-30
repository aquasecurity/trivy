package log

import (
	"github.com/aquasecurity/go-dep-parser/pkg/log"

	"go.uber.org/zap"
)

var Logger = log.NewLazyLogger(func() (*zap.SugaredLogger, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}
	return logger.Sugar(), nil
})

func SetLogger(l *zap.SugaredLogger) {
	Logger = log.NewLazyLogger(func() (*zap.SugaredLogger, error) { return l, nil })
}
