package utils

import (
	"log"
	"time"
)

func MustTimeParse(value string) *time.Time {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		log.Fatalln(err)
	}

	return &t
}
