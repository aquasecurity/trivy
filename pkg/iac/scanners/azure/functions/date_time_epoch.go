package functions

import (
	"time"

	smithyTime "github.com/aws/smithy-go/time"
)

func DateTimeFromEpoch(args ...interface{}) interface{} {
	if len(args) != 1 {
		return nil
	}

	epoch, ok := args[0].(int)
	if !ok {
		return nil
	}

	return smithyTime.ParseEpochSeconds(float64(epoch)).Format(time.RFC3339)
}

func DateTimeToEpoch(args ...interface{}) interface{} {
	if len(args) != 1 {
		return nil
	}

	dateTime, ok := args[0].(string)
	if !ok {
		return nil
	}

	parsed, err := time.Parse(time.RFC3339, dateTime)
	if err != nil {
		return nil
	}

	return int(parsed.Unix())
}
