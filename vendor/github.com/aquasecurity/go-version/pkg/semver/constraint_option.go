package semver

type conf struct {
	zeroPadding       bool
	includePreRelease bool
}

type ConstraintOption interface {
	apply(*conf)
}

type WithZeroPadding bool

func (o WithZeroPadding) apply(c *conf) {
	c.zeroPadding = bool(o)
}

type WithPreRelease bool

func (o WithPreRelease) apply(c *conf) {
	c.includePreRelease = bool(o)
}
