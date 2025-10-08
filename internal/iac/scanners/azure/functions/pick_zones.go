package functions

func PickZones(args ...any) any {
	if len(args) < 3 {
		return nil
	}
	numOfZones := 1

	if len(args) > 3 {
		numOfZones = min(args[3].(int), 3)
	}

	var zones []int

	for i := 1; i <= numOfZones; i++ {
		zones = append(zones, i)
	}

	return zones
}
