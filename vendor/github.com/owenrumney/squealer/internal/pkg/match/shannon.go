package match

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

func entropyCheck(data, bounds string) (withinBound bool, err error) {
	var entropy float64

	if data == "" {
		return false, nil
	}

	boundaries := strings.Split(bounds, ",")

	if len(boundaries) != 2 {
		return false, fmt.Errorf("failed to extract boundaries from bounds. %s", bounds)
	}

	min, err := strconv.ParseFloat(boundaries[0], 64)
	if err != nil {
		return false, fmt.Errorf("could not extract a valid minimum from bounds. %s", bounds)
	}

	max, err := strconv.ParseFloat(boundaries[1], 64)
	if err != nil {
		return false, fmt.Errorf("could not extract a valid maximum from bounds. %s", bounds)
	}

	for i := 0; i < 256; i++ {
		px := float64(strings.Count(data, string(byte(i)))) / float64(len(data))
		if px > 0 {
			entropy += -px * math.Log2(px)
		}
	}
	return entropy >= min && entropy <= max, nil
}
