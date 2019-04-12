package logger

import "go.uber.org/zap"

var Logger *zap.SugaredLogger

func InitLogger() (err error) {
	Logger, err = newLogger()
	if err != nil {
		return err
	}
	return nil

}

func newLogger() (*zap.SugaredLogger, error) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, err
	}
	return logger.Sugar(), nil
}
