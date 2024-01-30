package functions

func PickZones(args ...interface{}) interface{} {
	if len(args) < 3 {
		return nil
	}
	numOfZones := 1

	if len(args) > 3 {
		numOfZones = args[3].(int)
		if numOfZones > 3 {
			numOfZones = 3
		}
	}

	var zones []int

	for i := 1; i <= numOfZones; i++ {
		zones = append(zones, i)
	}

	return zones
}
